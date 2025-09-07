use std::fs::OpenOptions;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
use tracing::{error, info};

/// Connect to `/dev/ttyS22`, proxy raw I²C frames and append a counter.
///
/// The tap server continuously waits for the serial device to become
/// available. Once opened, it reads binary `[addr][cmd][len][data...]` frames
/// produced by the preload library. For each frame the first eight payload
/// bytes are echoed back followed by a little-endian `u64` counter. Logging the
/// complete frame in hexadecimal helps during troubleshooting.
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
        let file = loop {
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

            let len = hdr[2] as usize;
            let mut data = vec![0u8; len];
            if let Err(e) = reader.read_exact(&mut data) {
                error!("Read error: {}", e);
                break;
            }

            // Log the received frame in hex for visibility during debugging.
            let mut frame = hdr.to_vec();
            frame.extend_from_slice(&data);
            let hex: String = frame.iter().map(|b| format!("{:02x}", b)).collect();
            info!("Received: {}", hex);

            if data.len() >= 8 {
                // Construct the response: original addr/cmd, new length and
                // payload containing the echoed timestamp followed by a counter.
                let mut resp = Vec::with_capacity(3 + 16);
                resp.push(hdr[0]);
                resp.push(hdr[1]);
                resp.push(16);
                resp.extend_from_slice(&data[..8]);
                resp.extend_from_slice(&counter.to_le_bytes());

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
