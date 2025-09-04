use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Connect to `/dev/ttyS22`, log received messages, and optionally echo them
/// back. When the `I2C_PROXY_RAW` environment variable is set to any value
/// other than `0`, the program expects binary `[addr][cmd][len][data...]` frames
/// and prints the full frame as a hexadecimal string. Otherwise it treats the
/// input as newline-delimited text, logging each line and echoing it back with
/// an incrementing counter.
fn main() -> io::Result<()> {
    // Path to the serial port that the server will interact with.
    let path = Path::new("/dev/ttyS22");

    // Toggle raw mode via environment variable. Using an environment flag keeps
    // the binary lightweight while still allowing developers to switch between
    // framed binary traffic and human readable text without recompilation.
    let raw_mode = env::var("I2C_PROXY_RAW").map_or(false, |v| v != "0");

    // Open the device for reading and writing. If the path is not yet
    // available, wait and retry until it appears. Cloning the resulting handle
    // ensures the buffered reader does not interfere with writes.
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
        // In raw mode we operate on binary frames and echo them back verbatim.
        // Cloning the file descriptor gives us independent reader and writer
        // handles, allowing replies without disturbing the buffered reader.
        let mut reader = BufReader::new(file.try_clone()?);
        let mut writer = file;
        println!("Listening on {:?} (raw)...", path);
        loop {
            // Each frame begins with a three byte header: address, command and
            // payload length. An unexpected EOF simply terminates the loop.
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

            // Echo the raw frame back to the serial device so that connected
            // firmware expecting a reply can continue operating. Flushing the
            // writer immediately ensures the bytes are pushed out on the wire.
            writer.write_all(&frame)?;
            writer.flush()?;
        }
    } else {
        // Text mode mirrors the previous behavior: read lines, log them and
        // echo back a response with a monotonically increasing counter. The
        // clone ensures the writer is independent from the buffered reader.
        let reader = BufReader::new(file.try_clone()?);
        let mut writer = file;
        println!("Listening on {:?}...", path);
        let mut counter: u64 = 0;

        // Process each line received from the device.
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            println!("Received: {}", line);

            // Prepare a response that includes an incrementing counter and the
            // original data, then send it back to the device.
            let response = format!("{}: {}\n", counter, line);
            writer.write_all(response.as_bytes())?;
            writer.flush()?;
            counter += 1;
        }
    }

    Ok(())
}
