use std::fs::OpenOptions;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tracing::{error, info};
use libc::{F_GETFL, F_SETFL, O_NONBLOCK};

/// Command byte sent by the preload library to request a read response.
const READ_COMMAND: u8 = 0x01;

/// Read and discard any pending bytes from the provided serial device.
///
/// When the tap server reconnects to the proxy TTY there may be leftover
/// traffic from a previous run sitting in the kernel's buffer. This helper
/// drains all currently available data in a non-blocking fashion so the server
/// starts with a clean slate.
fn drain_stale(file: &mut std::fs::File) -> io::Result<()> {
    let fd = file.as_raw_fd();

    // Temporarily place the descriptor into non-blocking mode so `read` calls
    // return immediately when no data is present.
    let flags = unsafe { libc::fcntl(fd, F_GETFL, 0) };
    unsafe {
        libc::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    let mut buf = [0u8; 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,               // End of file: nothing more to drain.
            Ok(_) => continue,            // Keep draining until buffer is empty.
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    // Restore the original descriptor flags so subsequent I/O blocks as usual.
    unsafe {
        libc::fcntl(fd, F_SETFL, flags);
    }
    Ok(())
}

/// Connect to `/dev/ttyS22`, proxy raw I²C frames and maintain a counter.
///
/// The tap server continuously waits for the serial device to become
/// available. Once opened, it reads fixed-size ten byte frames formatted as
/// `[addr][cmd][d0]...[d7]` produced by the preload library. Write commands
/// (`cmd == 0`) log the eight data bytes in hexadecimal. Read requests
/// (`cmd == READ_COMMAND`) trigger a response containing a little-endian counter
/// value padded with zeros to a constant 62-byte length. The counter increments
/// after each successful read.
fn main() -> io::Result<()> {
    // Initialize tracing so execution can be followed via logs.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Serial device path used for communication with the preload library.
    let path = Path::new("/dev/ttyS22");

    // Run indefinitely, reconnecting if the device disappears or I/O fails.
    loop {
        // Wait for the device node to exist and open it for read/write.
        let mut file = loop {
            match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => break f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    info!("Waiting for {:?} to become available...", path);
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        // Clear any stale bytes that may be lingering in the device buffer from
        // a previous run before establishing the reader and writer handles.
        drain_stale(&mut file)?;

        let mut reader = BufReader::new(file.try_clone()?);
        let mut writer = file;
        let mut counter: u64 = 0;
        info!("Listening on {:?}...", path);

        loop {
            // Read the fixed 10-byte command frame. Any failure resets the
            // connection so the server can await a fresh device.
            let mut frame = [0u8; 10];
            if let Err(e) = reader.read_exact(&mut frame) {
                error!("Read error: {}", e);
                break;
            }

            let addr = frame[0];
            let cmd = frame[1];
            let data = &frame[2..];

            if cmd == READ_COMMAND {
                // Read request: send a 62-byte response containing the
                // little-endian counter followed by zero padding. The command
                // frame itself carries no additional information.
                info!("Read addr=0x{:02x} -> counter {}", addr, counter);

                let mut resp = Vec::with_capacity(62);
                let counter_bytes = counter.to_le_bytes();
                resp.extend_from_slice(&counter_bytes);
                resp.extend(std::iter::repeat(0).take(62 - counter_bytes.len()));

                if let Err(e) = writer.write_all(&resp) {
                    error!("Write error: {}", e);
                    break;
                }
                if let Err(e) = writer.flush() {
                    error!("Flush error: {}", e);
                    break;
                }
                counter += 1;
            } else {
                // Write command: log the eight data bytes in hexadecimal so
                // callers can observe the transmitted payload.
                let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                info!("Write addr=0x{:02x} data={}", addr, hex);
            }
        }

        info!(
            "Connection to {:?} closed. Waiting for the device to be ready again...",
            path
        );
    }
}
