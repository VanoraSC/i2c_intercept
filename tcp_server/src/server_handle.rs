//! TCP echo server implementation used for testing the tap server crate.
//!
//! The module exposes a small thread-per-connection echo server that binds a
//! non-blocking listening socket. Each accepted connection spawns a dedicated
//! reader thread and writer thread that communicate via an `mpsc` channel. The
//! reader collects bytes until a newline is observed or a 100 ms timeout expires
//! and forwards complete lines to the writer. The writer then echoes the line
//! back to the client. The [`start_echo_server`] helper starts the listener and
//! returns a [`ServerHandle`] that can be used to control the background
//! threads. The code is intentionally verbose and heavily documented in order to
//! satisfy the repository documentation requirements and to make the threading
//! behaviour easy to follow.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Amount of time the reader thread waits for a newline before discarding a
/// partial line. The value is derived from the user requirements and is used
/// whenever the read side has received some data but not a full line yet.
const LINE_TIMEOUT: Duration = Duration::from_millis(100);

/// Duration used when waiting for I/O readiness across the server.
///
/// The accept loop uses the value as the timeout passed to `poll`, the writer
/// thread relies on it when waiting for the socket to become writable, and the
/// reader thread sleeps for the same interval after observing a `WouldBlock`
/// read. Using a single constant keeps the behaviour consistent while still
/// allowing quick shutdown checks.
const IO_WAIT_TIMEOUT: Duration = Duration::from_millis(10);

/// Public handle returned by [`start_echo_server`] that can be used to query
/// the bound address or to shut the server down when tests have finished.
///
/// The handle owns an `Arc<AtomicBool>` flag shared with the listener thread.
/// Calling [`ServerHandle::shutdown`] sets the flag and waits for the listener
/// thread to terminate so resources are reclaimed before the handle is dropped.
pub struct ServerHandle {
    /// Shared shutdown flag toggled by the [`ServerHandle::shutdown`] method.
    shutdown_flag: Arc<AtomicBool>,
    /// Join handle for the background listener thread spawned by
    /// [`start_echo_server`]. The handle is wrapped in an `Option` so it can be
    /// taken during shutdown without requiring mutable borrows afterwards.
    listener_thread: Option<JoinHandle<()>>,
    /// Address bound by the TCP listener. Storing the value allows tests to
    /// determine which port was selected when binding to `127.0.0.1:0`.
    local_addr: SocketAddr,
}

impl ServerHandle {
    /// Query the socket address currently in use by the listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Request a graceful server shutdown and wait for the listener thread to
    /// finish.
    ///
    /// Multiple calls are allowed; only the first call will attempt to join the
    /// listener thread because the handle is moved out of the `Option`.
    pub fn shutdown(&mut self) {
        // Signal the background thread that new connections should no longer be
        // accepted.
        self.shutdown_flag.store(true, Ordering::Relaxed);

        // Join the listener thread exactly once, ignoring panics because tests
        // can still proceed even if the background task unwinds unexpectedly.
        if let Some(handle) = self.listener_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ServerHandle {
    /// Ensure the server stops when the [`ServerHandle`] goes out of scope.
    ///
    /// Tests may call [`ServerHandle::shutdown`] explicitly, but the drop
    /// implementation provides a safety net so the background thread does not
    /// leak even if the caller forgets to do so.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start a TCP echo server that binds the provided address and spawns a
/// background thread to accept incoming connections.
///
/// The listener is configured to be non-blocking so the accept loop can poll
/// for new clients while periodically checking the shutdown flag. Each
/// connection is handled in a dedicated thread which in turn spawns two worker
/// threads: one for reading and one for writing.
pub fn start_echo_server(addr: &str) -> io::Result<ServerHandle> {
    // Create the listening socket and configure it for non-blocking operation
    // as required by the user instructions.
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let local_addr = listener.local_addr()?;

    // Shared shutdown flag used to stop the background listener loop.
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let accept_shutdown = shutdown_flag.clone();

    // Spawn the background listener thread. A named thread makes debugging
    // easier and documents intent when inspected in stack traces.
    let listener_thread = thread::Builder::new()
        .name("echo_accept".to_string())
        .spawn(move || accept_loop(listener, accept_shutdown))?;

    Ok(ServerHandle {
        shutdown_flag,
        listener_thread: Some(listener_thread),
        local_addr,
    })
}

/// Continuously accept new connections until the shutdown flag is toggled.
fn accept_loop(listener: TcpListener, shutdown_flag: Arc<AtomicBool>) {
    println!(
        "Echo server listening on {} (thread: echo_accept)",
        listener.local_addr().unwrap()
    );

    // Run until tests request shutdown. The non-blocking listener ensures the
    // loop progresses even when no clients are connecting.
    while !shutdown_flag.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, addr)) => {
                // Mark the accepted stream as non-blocking so the reader thread
                // can implement the 100 ms timeout without blocking the thread
                // indefinitely.
                if let Err(err) = stream.set_nonblocking(true) {
                    println!(
                        "Failed to configure non-blocking stream for {}: {}",
                        addr, err
                    );
                    continue;
                }

                // Spawn a dedicated handler thread for the connection. The
                // handler is responsible for starting the reader and writer
                // workers and cleaning up when the client disconnects.
                if let Err(err) = thread::Builder::new()
                    .name(format!("echo_connection_{}", addr))
                    .spawn(move || handle_connection(stream, addr))
                {
                    println!("Failed to spawn handler for {}: {}", addr, err);
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                // No client is currently waiting. Use `poll` to block until the
                // listener becomes readable or the timeout elapses, which avoids
                // spinning while still allowing regular shutdown checks.
                if let Err(poll_err) = wait_for_listener_event(&listener, IO_WAIT_TIMEOUT) {
                    println!("Polling listener for new connections failed: {}", poll_err);
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                // Interrupted syscalls are expected; simply retry.
                continue;
            }
            Err(err) => {
                // Any other error is logged and the loop continues. Errors are
                // not fatal because the shutdown flag may still require
                // servicing.
                println!("Accept error: {}", err);
                if let Err(poll_err) = wait_for_listener_event(&listener, IO_WAIT_TIMEOUT) {
                    println!("Polling listener after accept error failed: {}", poll_err);
                }
            }
        }
    }

    println!("Echo server listener shutting down");
}

/// Wait for a specific readiness event on an arbitrary file descriptor.
///
/// This helper centralises the `libc::poll` invocation so both the listener and
/// the per-connection workers can block until the underlying socket is ready
/// for the desired operation. The timeout is expressed as a [`Duration`] to
/// keep the API ergonomic for callers while the function performs the necessary
/// conversion to the millisecond granularity expected by `poll`.
fn wait_for_fd_event(fd: RawFd, events: libc::c_short, timeout: Duration) -> io::Result<()> {
    // Clamp the timeout so it fits within the `c_int` range expected by `poll`.
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;

    let mut poll_fd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };

    loop {
        // SAFETY: The poll file descriptor array is valid for the duration of
        // the call because it points to stack memory owned by this function. The
        // length argument is set to `1`, matching the single entry array.
        let result = unsafe { libc::poll(&mut poll_fd as *mut _, 1, timeout_ms) };
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                // Retry when interrupted so transient signals do not bubble up
                // as errors.
                continue;
            }
            return Err(err);
        }

        // Either readiness was observed or the call timed out. In both cases
        // the caller should retry the associated I/O operation, so the function
        // simply returns.
        return Ok(());
    }
}

/// Block on the listening socket until it becomes readable or the timeout
/// elapses.
///
/// The helper wraps [`wait_for_fd_event`] so the accept loop can wait for new
/// connections without falling back to `thread::sleep`. Using `poll` ensures the
/// loop responds quickly when a client arrives while also enforcing a timeout so
/// the shutdown flag is checked regularly.
fn wait_for_listener_event(listener: &TcpListener, timeout: Duration) -> io::Result<()> {
    wait_for_fd_event(listener.as_raw_fd(), libc::POLLIN, timeout)
}

/// Handle a single TCP client connection.
///
/// The connection thread sets up the reader and writer workers, waits for them
/// to complete, and ensures the socket is shut down when work is finished.
fn handle_connection(stream: TcpStream, peer_addr: SocketAddr) {
    println!("Accepted connection from {}", peer_addr);

    // Channel used to forward messages from the reader thread to the writer
    // thread. The channel also allows other helpers to enqueue additional
    // responses via [`send_bytes`].
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    // Clone the stream so the reader and writer each own a handle. Clones share
    // the same underlying socket which is acceptable because the operations are
    // performed on separate threads.
    let writer_stream = match stream.try_clone() {
        Ok(clone) => clone,
        Err(err) => {
            println!(
                "Failed to clone stream for {}: {}. Dropping connection.",
                peer_addr, err
            );
            return;
        }
    };

    // Spawn the writer thread before the reader so the channel has a consumer
    // ready as soon as the reader receives the first line.
    let writer_handle = match thread::Builder::new()
        .name(format!("echo_writer_{}", peer_addr))
        .spawn(move || writer_thread(writer_stream, rx, peer_addr))
    {
        Ok(handle) => handle,
        Err(err) => {
            println!("Failed to spawn writer thread for {}: {}", peer_addr, err);
            return;
        }
    };

    let reader_handle = match thread::Builder::new()
        .name(format!("echo_reader_{}", peer_addr))
        .spawn(move || reader_thread(stream, tx, peer_addr))
    {
        Ok(handle) => handle,
        Err(err) => {
            println!("Failed to spawn reader thread for {}: {}", peer_addr, err);
            if let Err(join_err) = writer_handle.join() {
                println!(
                    "Writer thread for {} panicked while unwinding: {:?}",
                    peer_addr, join_err
                );
            }
            return;
        }
    };

    // Wait for both worker threads to exit. Joining ensures resources are
    // cleaned up deterministically and avoids silently ignoring panics.
    if let Err(err) = reader_handle.join() {
        println!("Reader thread for {} panicked: {:?}", peer_addr, err);
    }

    if let Err(err) = writer_handle.join() {
        println!("Writer thread for {} panicked: {:?}", peer_addr, err);
    }

    println!("Connection handler for {} finished", peer_addr);
}

/// Reader worker executed on its own thread for each connection.
///
/// The reader accumulates bytes until it encounters a newline character. If the
/// newline does not arrive within [`LINE_TIMEOUT`], the partial buffer is
/// dropped so the next chunk starts fresh. Completed lines are sent to the
/// writer thread using the [`send_bytes`] helper.
fn reader_thread(mut stream: TcpStream, sender: Sender<Vec<u8>>, peer_addr: SocketAddr) {
    let mut buffer = Vec::new();
    let mut first_byte_time: Option<Instant> = None;
    let mut temp = [0u8; 1024];

    loop {
        match stream.read(&mut temp) {
            Ok(0) => {
                // A read of zero bytes indicates the peer closed the
                // connection. Log the event and exit the loop so the sender is
                // dropped, signalling the writer to finish.
                println!("Client {} disconnected", peer_addr);
                break;
            }
            Ok(n) => {
                // Record the time when the first byte of a potential line was
                // seen so the timeout can be enforced if the newline never
                // arrives.
                if first_byte_time.is_none() {
                    first_byte_time = Some(Instant::now());
                }

                buffer.extend_from_slice(&temp[..n]);

                // Process every complete line currently buffered. Additional
                // bytes may already be present if the client transmitted
                // multiple lines at once.
                while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                    // Drain the bytes up to and including the newline so the
                    // next iteration starts at the beginning of the next line.
                    let line: Vec<u8> = buffer.drain(..=pos).collect();

                    if let Err(err) = send_bytes(&sender, &line) {
                        println!("Failed to queue response for {}: {}", peer_addr, err);
                        return;
                    }

                    // Reset the timer if the buffer is empty. If extra bytes
                    // remain (the start of the next line), treat the current
                    // instant as the beginning of that new line.
                    first_byte_time = if buffer.is_empty() {
                        None
                    } else {
                        Some(Instant::now())
                    };
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                // No data is currently available. If we have buffered bytes,
                // check whether the timeout has expired and drop the partial
                // line if necessary.
                if let Some(start) = first_byte_time {
                    if start.elapsed() >= LINE_TIMEOUT {
                        println!(
                            "Discarding partial line from {} after {:?}",
                            peer_addr, LINE_TIMEOUT
                        );
                        buffer.clear();
                        first_byte_time = None;
                    }
                }

                thread::sleep(IO_WAIT_TIMEOUT);
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                // Interrupted reads simply retry without logging noise.
                continue;
            }
            Err(err) => {
                // Any other error is fatal to the connection. The writer will
                // subsequently exit once the channel is dropped.
                println!("Read error from {}: {}", peer_addr, err);
                break;
            }
        }
    }

    // Explicitly drop the sender so the writer thread observes channel closure
    // even if the loop breaks early due to errors.
    drop(sender);
    let _ = stream.shutdown(Shutdown::Both);
}

/// Writer worker executed on its own thread for each connection.
///
/// The writer waits for lines forwarded by the reader via the channel. Each
/// message is written back to the client verbatim. Errors encountered while
/// writing are logged and cause the thread to terminate, cleaning up the
/// connection resources.
fn writer_thread(mut stream: TcpStream, receiver: Receiver<Vec<u8>>, peer_addr: SocketAddr) {
    while let Ok(message) = receiver.recv() {
        if let Err(err) = write_all_nonblocking(&mut stream, &message) {
            println!("Write error to {}: {}", peer_addr, err);
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    }

    println!("Writer thread for {} exiting", peer_addr);
}

/// Helper that sends the provided payload through the writer channel.
///
/// The function exists to satisfy the user requirement that a dedicated helper
/// can forward arbitrary byte arrays to the writer thread. It clones the
/// provided slice into a `Vec<u8>` and forwards it through the supplied sender.
/// The helper is publicly exposed so tests or other modules can reuse the same
/// behaviour when interacting with the server.
pub fn send_bytes(
    sender: &Sender<Vec<u8>>,
    payload: &[u8],
) -> Result<(), mpsc::SendError<Vec<u8>>> {
    sender.send(payload.to_vec())
}

/// Wait for the provided TCP stream to become writable or for the timeout to
/// elapse.
///
/// The helper allows the writer thread to avoid sleeping blindly when the
/// socket reports `WouldBlock`. Instead it leverages the shared
/// [`wait_for_fd_event`] logic so the thread wakes up as soon as the stream is
/// ready to accept more data or the timeout expires, maintaining responsiveness
/// to shutdown conditions.
fn wait_for_stream_writable(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    wait_for_fd_event(stream.as_raw_fd(), libc::POLLOUT, timeout)
}

/// Write the full contents of `data` to a non-blocking stream.
///
/// The helper loops until every byte has been transmitted. `WouldBlock` and
/// `Interrupted` errors are handled by retrying: the former waits for the socket
/// to become writable using [`wait_for_stream_writable`], while the latter is
/// ignored so the write is attempted again. A `WriteZero` error is treated as
/// fatal to avoid busy looping if the socket is unexpectedly closed.
fn write_all_nonblocking(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let mut offset = 0;

    while offset < data.len() {
        match stream.write(&data[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket closed during write",
                ));
            }
            Ok(n) => {
                offset += n;
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                wait_for_stream_writable(stream, IO_WAIT_TIMEOUT)?;
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}
