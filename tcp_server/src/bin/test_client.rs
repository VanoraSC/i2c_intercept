//! Minimal TCP test client used to exercise the echo server during
//! development.
//!
//! The binary continuously attempts to connect to the server, transmits the
//! current UTC timestamp every second and prints the echoed responses. The
//! implementation mirrors the non-blocking approach used by the server so
//! behaviour is deterministic and resilient to unexpected network stalls. The
//! code contains extensive commentary to comply with the repository
//! documentation requirements and to clarify the rationale behind each step of
//! the client state machine.

use std::env;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};

/// Default TCP endpoint used when no explicit address is provided on the
/// command line. The chosen port is arbitrary but avoids well-known services so
/// it is unlikely to clash with system daemons during development.
const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:4000";

/// Timeout applied to all socket readiness checks. The value matches the
/// requirements stated by the user request and ensures the client does not
/// block indefinitely when the server becomes unresponsive.
const IO_TIMEOUT: Duration = Duration::from_millis(100);

/// Delay applied between reconnection attempts. A short pause prevents the
/// client from busy-looping when the server is temporarily unavailable while
/// still providing quick recovery once it comes back online.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

fn main() {
    // Determine the destination address. The first command line argument takes
    // precedence while falling back to [`DEFAULT_SERVER_ADDR`] keeps the binary
    // ergonomic for local development sessions.
    let server_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SERVER_ADDR.to_string());

    // Shared flag toggled by the Ctrl+C handler. Each loop iteration checks the
    // flag to decide whether the program should continue running.
    let running = Arc::new(AtomicBool::new(true));
    let signal_flag = running.clone();
    if let Err(err) = ctrlc::set_handler(move || {
        // Mark the program as finished and provide visual feedback so the user
        // knows the interrupt request was received.
        signal_flag.store(false, Ordering::SeqCst);
        println!("Received interrupt, shutting down client...");
    }) {
        eprintln!("Failed to install Ctrl+C handler: {err}");
        return;
    }

    println!("Starting TCP test client. Connecting to {server_addr}...");

    // Run the connection loop and surface any terminal error to the user.
    if let Err(err) = client_loop(&server_addr, &running) {
        if err.kind() != ErrorKind::Interrupted {
            eprintln!("Client terminated due to unrecoverable error: {err}");
        }
    }

    println!("Client exited cleanly");
}

/// Primary control loop that manages the connection lifecycle.
///
/// The function repeatedly tries to connect to the server, processes the
/// established session and handles transient failures by reconnecting after a
/// short delay. The loop terminates when the shared `running` flag is toggled by
/// the Ctrl+C handler.
fn client_loop(server_addr: &str, running: &Arc<AtomicBool>) -> io::Result<()> {
    while running.load(Ordering::SeqCst) {
        match TcpStream::connect(server_addr) {
            Ok(stream) => {
                println!("Connected to {server_addr}");

                // Delegate the non-blocking communication to a helper. Any
                // timeout or connection error is logged before attempting to
                // reconnect.
                match handle_connection(stream, running) {
                    Ok(()) => {
                        // Normal termination means the Ctrl+C handler asked the
                        // loop to stop. Break early to avoid an unnecessary
                        // reconnect delay.
                        break;
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => {
                        break;
                    }
                    Err(err) if err.kind() == ErrorKind::TimedOut => {
                        eprintln!("Communication with {server_addr} timed out. Reconnecting...");
                    }
                    Err(err) => {
                        eprintln!("Connection to {server_addr} failed: {err}");
                    }
                }
            }
            Err(err) => {
                eprintln!("Unable to connect to {server_addr}: {err}");
            }
        }

        // Honour the shutdown request immediately without waiting for the delay
        // when the user pressed Ctrl+C while the connection was down.
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Pause briefly before the next attempt to avoid hammering the server
        // when repeated failures occur.
        sleep_with_checks(running, RECONNECT_DELAY);
    }

    Ok(())
}

/// Handle an established TCP session using non-blocking I/O.
///
/// The function configures the socket for non-blocking mode, sends the current
/// UTC timestamp once per second and reads back responses until an error is
/// observed or the user aborts the program. Any error is surfaced to the caller
/// so the connection loop can decide whether to reconnect or shut down.
fn handle_connection(mut stream: TcpStream, running: &Arc<AtomicBool>) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let fd = stream.as_raw_fd();

    // Buffer used to accumulate incoming bytes until a newline is observed. The
    // buffer is reused across iterations to avoid reallocations in the steady
    // state.
    let mut inbound = Vec::with_capacity(256);

    while running.load(Ordering::SeqCst) {
        let timestamp = format_current_utc();
        let mut payload = timestamp.as_bytes();

        // Send the newline-terminated timestamp to the server, waiting for the
        // socket to become writable before each write attempt.
        while !payload.is_empty() {
            if wait_for_fd_event(fd, libc::POLLOUT, IO_TIMEOUT)?.is_none() {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for socket to become writable",
                ));
            }

            match stream.write(payload) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "socket closed while sending timestamp",
                    ));
                }
                Ok(bytes_written) => {
                    payload = &payload[bytes_written..];
                }
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                    // The socket reported readiness but produced a `WouldBlock`
                    // error. Retry the write after the next poll cycle.
                    continue;
                }
                Err(err) => return Err(err),
            }
        }

        // Retrieve and print the echoed response. The helper returns an error
        // whenever the server closes the connection or the 100 ms timeout is
        // reached.
        let response = read_line_nonblocking(&mut stream, fd, running, &mut inbound)?;
        println!("Server replied: {response}");

        // Wait for roughly one second before sending the next timestamp. The
        // helper allows the loop to observe Ctrl+C quickly even while waiting.
        sleep_with_checks(running, Duration::from_secs(1));
    }

    Ok(())
}

/// Wait for the provided file descriptor to become ready for the specified
/// events using `poll`.
///
/// The helper returns `Ok(None)` when the timeout expires, `Ok(Some(_))` when an
/// event occurs and propagates any fatal poll error.
fn wait_for_fd_event(
    fd: libc::c_int,
    events: libc::c_short,
    timeout: Duration,
) -> io::Result<Option<libc::c_short>> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    let mut poll_fd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };

    loop {
        // SAFETY: the pollfd structure references stack memory that stays alive
        // for the duration of the call, making the pointer passed to `poll`
        // valid. Only one file descriptor is monitored, therefore the call is
        // straightforward.
        let rc = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };

        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        } else if rc == 0 {
            return Ok(None);
        }

        // Surface hang-ups and generic socket errors as explicit I/O errors so
        // the caller can attempt a clean reconnection.
        if poll_fd.revents & libc::POLLERR != 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                "socket error reported by poll",
            ));
        }
        if poll_fd.revents & libc::POLLHUP != 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "remote side closed the connection",
            ));
        }
        if poll_fd.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                "invalid file descriptor for poll",
            ));
        }

        return Ok(Some(poll_fd.revents));
    }
}

/// Read a single newline-terminated line using non-blocking operations.
fn read_line_nonblocking(
    stream: &mut TcpStream,
    fd: libc::c_int,
    running: &Arc<AtomicBool>,
    inbound: &mut Vec<u8>,
) -> io::Result<String> {
    loop {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "client shutdown requested",
            ));
        }

        if wait_for_fd_event(fd, libc::POLLIN, IO_TIMEOUT)?.is_none() {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "timed out waiting for data from server",
            ));
        }

        let mut buf = [0u8; 512];
        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "server closed the connection",
                ));
            }
            Ok(bytes_read) => {
                inbound.extend_from_slice(&buf[..bytes_read]);
                if let Some(position) = inbound.iter().position(|&b| b == b'\n') {
                    let raw_line = inbound.drain(..=position).collect::<Vec<u8>>();
                    match String::from_utf8(raw_line) {
                        Ok(mut text) => {
                            if !text.is_empty() && text.ends_with('\n') {
                                // Trim the newline delimiter because `println!`
                                // appends its own line ending.
                                text.pop();
                            }
                            return Ok(text);
                        }
                        Err(err) => {
                            return Err(io::Error::new(ErrorKind::InvalidData, err));
                        }
                    }
                }
            }
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Convert the current system time to an RFC 3339 UTC string with millisecond
/// precision. A trailing newline is appended so the server can treat the value
/// as a line-based protocol message.
fn format_current_utc() -> String {
    let now = Utc::now();
    let mut formatted = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    formatted.push('\n');
    formatted
}

/// Sleep for the requested duration while periodically checking whether the
/// user requested shutdown. The helper ensures the client reacts quickly to
/// Ctrl+C even when paused between transmissions.
fn sleep_with_checks(running: &Arc<AtomicBool>, total: Duration) {
    let mut remaining = total;
    let check_interval = Duration::from_millis(100);

    while remaining > Duration::ZERO && running.load(Ordering::SeqCst) {
        let step = if remaining > check_interval {
            check_interval
        } else {
            remaining
        };

        thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
}
