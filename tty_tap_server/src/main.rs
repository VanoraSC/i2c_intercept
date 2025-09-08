use std::fs::OpenOptions;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::Duration;
use tracing::{error, info};
use libc::{F_GETFL, F_SETFL, O_NONBLOCK};

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
/// available. Once opened, it reads binary `[addr][cmd][len][data...]` frames
/// produced by the preload library. Write commands (`cmd == 0`) are logged in a
/// human readable hexadecimal representation. Read requests (`cmd == 1`) cause
/// the server to log the request and send back the current counter value padded
/// with zeros to a fixed length of 62 bytes. The counter increments after every
/// serviced read.
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
            // Each frame begins with a three byte header: address, command and
            // payload length. Any read failure causes the connection to reset.
            let mut hdr = [0u8; 3];
            if let Err(e) = reader.read_exact(&mut hdr) {
                error!("Read error: {}", e);
                break;
            }

            let addr = hdr[0];
            let cmd = hdr[1];
            let len = hdr[2] as usize;

            if cmd == 0 {
                // Write command: read the payload and log it in hexadecimal.
                let mut data = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut data) {
                    error!("Read error: {}", e);
                    break;
                }
                let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                info!("Write addr=0x{:02x} data={}", addr, hex);
            } else {
                // Read request: regardless of the requested length, always send
                // back a 62‑byte payload consisting of the little-endian
                // counter value padded with zeros. The length byte in the
                // header is ignored by the receiver so it is fixed to 62 to
                // reflect the transmitted payload size.
                info!(
                    "Read addr=0x{:02x} len={} -> counter {}",
                    addr, len, counter
                );

                let mut resp = Vec::with_capacity(3 + 62);
                resp.push(addr);
                resp.push(cmd);
                resp.push(62u8);
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
            }
        }

        info!(
            "Connection to {:?} closed. Waiting for the device to be ready again...",
            path
        );
    }
}
