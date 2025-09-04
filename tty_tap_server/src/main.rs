use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Connect to `/dev/ttyS22`, log received messages, and optionally echo them
/// back. When the `I2C_PROXY_RAW` environment variable is set to any value
/// other than `0`, the program expects binary `[addr][cmd][len][data...]` frames
/// and prints the full frame as a hexadecimal string. Otherwise it reads
/// eight-byte little-endian timestamps, logging each value and echoing it back
/// as a textual line with an incrementing counter.
fn main() -> io::Result<()> {
    // Path to the serial port that the server will interact with.
    let path = Path::new("/dev/ttyS22");

    // Toggle raw mode via environment variable. Using an environment flag keeps
    // the binary lightweight while still allowing developers to switch between
    // framed binary traffic and human readable text without recompilation.
    let raw_mode = env::var("I2C_PROXY_RAW").map_or(false, |v| v != "0");

    // Keep the tap server alive indefinitely. Each iteration waits for the
    // device to appear, processes traffic until the peer closes the connection
    // and then loops back to wait again. This mirrors the behaviour of the I²C
    // time writer which may terminate and later reconnect.
    loop {
        // Open the device for reading and writing. If the path is not yet
        // available, wait and retry until it appears. Cloning the resulting
        // handle ensures the buffered reader does not interfere with writes.
        let file = loop {
            match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(f) => break f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    println!("Waiting for {:?} to become available...", path);
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        if raw_mode {
            // In raw mode we operate on binary frames and echo them back
            // verbatim. Cloning the file descriptor gives us independent reader
            // and writer handles, allowing replies without disturbing the
            // buffered reader.
            let mut reader = BufReader::new(file.try_clone()?);
            let mut writer = file;
            println!("Listening on {:?} (raw)...", path);
            loop {
                // Each frame begins with a three byte header: address, command
                // and payload length. An unexpected EOF simply terminates the
                // loop so we can return to the waiting state.
                let mut hdr = [0u8; 3];
                if let Err(e) = reader.read_exact(&mut hdr) {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        return Err(e);
                    }
                    break;
                }
                let len = hdr[2] as usize;
                // Read the payload based on the length specified in the header.
                let mut data = vec![0u8; len];
                reader.read_exact(&mut data)?;

                // Assemble the full frame and render it as a concatenated hex
                // string for easy inspection.
                let mut frame = hdr.to_vec();
                frame.extend_from_slice(&data);
                let hex: String = frame.iter().map(|b| format!("{:02x}", b)).collect();
                println!("Received (raw): {}", hex);

                // Echo the raw frame back to the serial device so that
                // connected firmware expecting a reply can continue operating.
                // Flushing the writer immediately ensures the bytes are pushed
                // out on the wire.
                writer.write_all(&frame)?;
                writer.flush()?;
            }
        } else {
            // In text mode the connected writer sends raw `u64` timestamps.
            // Clone the file descriptor so reading and writing can occur
            // independently.
            let mut reader = file.try_clone()?;
            let mut writer = file;
            println!("Listening on {:?}...", path);
            let mut counter: u64 = 0;

            loop {
                // Attempt to read exactly eight bytes representing a
                // little-endian `u64` of seconds since the UNIX epoch. Any
                // unexpected EOF ends the loop while other errors are surfaced
                // to the caller.
                let mut buf = [0u8; 8];
                if let Err(e) = reader.read_exact(&mut buf) {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        return Err(e);
                    }
                    break;
                }
                let secs = u64::from_le_bytes(buf);
                println!("Received: {}", secs);

                // Echo the timestamp back as an ASCII line that includes a
                // monotonically increasing counter. The trailing newline matches
                // the expectations of the I²C time writer's read loop.
                let response = format!("{}: {}\n", counter, secs);
                writer.write_all(response.as_bytes())?;
                writer.flush()?;
                counter += 1;
            }
        }

        // If we exit the inner processing loop the peer has closed the
        // connection. Drop the file handle and return to the top of the outer
        // loop where we will wait for the device to reappear.
        println!(
            "Connection to {:?} closed. Waiting for the device to be ready again...",
            path
        );
    }
}
