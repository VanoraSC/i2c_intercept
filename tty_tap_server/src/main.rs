use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
use serde_json::Value;
use tracing::{error, info, trace, warn};

/// Decode a hexadecimal string into a vector of bytes.
///
/// The JSON emitted by the I²C redirect library represents binary payloads as
/// lower-case hexadecimal strings.  To reconstruct the original bytes we
/// manually parse the string two characters at a time.  Returning `None` when
/// encountering invalid characters or odd-length input allows the caller to
/// gracefully handle malformed data without panicking or pulling in additional
/// dependencies just for hex decoding.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    trace!("decode_hex len={}", s.len());
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        let byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

/// Connect to `/dev/ttyS22`, interpret incoming traffic from the I²C redirect
/// library and provide suitable responses. When the `I2C_PROXY_RAW`
/// environment variable is set to any value other than `0`, the program
/// expects binary `[addr][cmd][len][data...]` frames and prints the full frame
/// as a hexadecimal string while echoing the frame back unmodified.
///
/// In the default mode the redirect library sends newline separated JSON
/// objects describing I²C activity.  For `write` events the JSON contains a
/// `data_hex` field holding the transmitted bytes.  This server decodes the
/// payload, logs the embedded timestamp and replies with the same eight bytes
/// followed by an additional little-endian `u64` counter so client programs can
/// verify that the round-trip occurred.
fn main() -> io::Result<()> {
    // Initialize tracing so the tap server emits detailed execution logs.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Path to the serial port that the server will interact with.
    let path = Path::new("/dev/ttyS22");

    // Toggle raw mode via environment variable. Using an environment flag keeps
    // the binary lightweight while still allowing developers to switch between
    // framed binary traffic and human readable text without recompilation.
    let raw_mode = env::var("I2C_PROXY_RAW").map_or(false, |v| v != "0");
    trace!("raw_mode={} path={:?}", raw_mode, path);

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
                    info!("Waiting for {:?} to become available...", path);
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
            info!("Listening on {:?} (raw)...", path);
            loop {
                // Each frame begins with a three byte header: address, command
                // and payload length. Any I/O error—including the device being
                // unplugged—terminates the loop so the outer loop can
                // re-establish the connection.
                let mut hdr = [0u8; 3];
                if let Err(e) = reader.read_exact(&mut hdr) {
                    error!("Read error: {}", e);
                    break;
                }

                let len = hdr[2] as usize;
                // Read the payload based on the length specified in the header
                // and break on any failure to allow reconnection attempts.
                let mut data = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut data) {
                    error!("Read error: {}", e);
                    break;
                }

                // Assemble the full frame and render it as a concatenated hex
                // string for easy inspection.
                let mut frame = hdr.to_vec();
                frame.extend_from_slice(&data);
                let hex: String = frame.iter().map(|b| format!("{:02x}", b)).collect();
                info!("Received (raw): {}", hex);

                // Echo the raw frame back to the serial device so that
                // connected firmware expecting a reply can continue operating.
                // Flushing the writer immediately ensures the bytes are pushed
                // out on the wire. Any write error is treated as a lost
                // connection and triggers a return to the waiting state.
                if let Err(e) = writer.write_all(&frame) {
                    error!("Write error: {}", e);
                    break;
                }
                if let Err(e) = writer.flush() {
                    error!("Flush error: {}", e);
                    break;
                }
            }
        } else {
            // In JSON mode the redirect library delivers newline separated
            // objects describing I²C operations.  We parse each line and, when a
            // `write` event is observed, decode the hexadecimal payload and
            // craft a binary response.

            // Use a buffered reader for convenient line-based processing.  The
            // file descriptor is cloned so writes do not disturb the reader's
            // internal state.
            let reader = BufReader::new(file.try_clone()?);
            let mut writer = file;
            info!("Listening on {:?}...", path);
            let mut counter: u64 = 0;

            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => { error!("Read error: {}", e); break; }
                };
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }

                match serde_json::from_str::<Value>(trimmed) {
                    Ok(v) => {
                        // Only `write` events contain payload bytes that need to
                        // be echoed back to the client. Other event types are
                        // logged and ignored.
                        let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                        if typ == "write" {
                            if let Some(hex) = v.get("data_hex").and_then(|d| d.as_str()) {
                                if let Some(bytes) = decode_hex(hex) {
                                    if bytes.len() >= 8 {
                                        let secs = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                                        info!("Received: {}", secs);
                                        let mut resp = Vec::with_capacity(16);
                                        resp.extend_from_slice(&bytes[0..8]);
                                        resp.extend_from_slice(&counter.to_le_bytes());
                                        if let Err(e) = writer.write_all(&resp) { error!("Write error: {}", e); break; }
                                        if let Err(e) = writer.flush() { error!("Flush error: {}", e); break; }
                                        counter += 1;
                                    } else {
                                        warn!("write event too short");
                                    }
                                } else {
                                    warn!("invalid hex payload: {}", hex);
                                }
                            }
                        } else {
                            trace!("Ignoring event: {}", typ);
                        }
                    }
                    Err(_) => trace!("(raw) {}", trimmed),
            }
        }
        }

        // If we exit the inner processing loop the peer has closed the
        // connection. Drop the file handle and return to the top of the outer
        // loop where we will wait for the device to reappear.
        info!(
            "Connection to {:?} closed. Waiting for the device to be ready again...",
            path
        );
    }
}
