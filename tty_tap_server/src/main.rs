use serde_json::Value;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
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
    if s.len() % 2 != 0 {
        return None;
    }
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
/// objects describing I²C activity. `write` events include a `data_hex` field
/// containing the bytes transmitted by the original program. The tap server now
/// remembers that payload and defers any response until a subsequent `read`
/// event arrives. When a `read` is observed the server echoes the most recently
/// written bytes back to the serial device, allowing the client to retrieve the
/// data it previously supplied. Consecutive reads without an intervening write
/// all receive the same stored payload.
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
            // objects describing I²C operations.  We parse each line and react
            // to `write` and `read` events.  Write payloads are stored so a later
            // read can retrieve them.

            // Use a buffered reader for convenient line-based processing.  The
            // file descriptor is cloned so writes do not disturb the reader's
            // internal state.
            let reader = BufReader::new(file.try_clone()?);
            let mut writer = file;
            info!("Listening on {:?}...", path);

            // Keep track of the most recent bytes supplied by a `write` command.
            // When a `read` event is observed these bytes are echoed back to the
            // serial port.
            let mut last_write: Option<Vec<u8>> = None;

            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Read error: {}", e);
                        break;
                    }
                };
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match serde_json::from_str::<Value>(trimmed) {
                    Ok(v) => {
                        // Determine the kind of event being reported and handle
                        // only the `write` and `read` varieties. Any other type
                        // is ignored but logged at the TRACE level for
                        // diagnostics.
                        let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                        if typ == "write" {
                            // Decode the hexadecimal representation of the
                            // payload and stash it so the next `read` event can
                            // return the same bytes to the client.
                            if let Some(hex) = v.get("data_hex").and_then(|d| d.as_str()) {
                                if let Some(bytes) = decode_hex(hex) {
                                    trace!("stored {} byte write", bytes.len());
                                    last_write = Some(bytes);
                                } else {
                                    warn!("invalid hex payload: {}", hex);
                                }
                            }
                        } else if typ == "read" {
                            // A read request asks for previously written data.
                            // If we have such data available, echo it back to
                            // the serial device. The optional `len` field limits
                            // how many bytes are returned.
                            if let Some(ref data) = last_write {
                                let req_len = v
                                    .get("len")
                                    .and_then(|l| l.as_u64())
                                    .map(|l| l as usize)
                                    .unwrap_or(data.len());
                                // Cap the response length to both the requested
                                // amount and the number of bytes we actually
                                // have available from the prior write.
                                let resp_len = req_len.min(data.len());

                                // Log the details of the read so developers can
                                // easily trace interactions between the client
                                // and tap server.
                                info!(
                                    "read request for {} bytes, returning {} bytes",
                                    req_len, resp_len
                                );
                                trace!(
                                    "read response bytes: {}",
                                    data[..resp_len]
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<String>()
                                );

                                if let Err(e) = writer.write_all(&data[..resp_len]) {
                                    error!("Write error: {}", e);
                                    break;
                                }
                                if let Err(e) = writer.flush() {
                                    error!("Flush error: {}", e);
                                    break;
                                }
                            } else {
                                // No prior write means we have nothing to send
                                // back. Log at INFO level so the absence of
                                // data is visible when debugging communication
                                // issues.
                                info!("read request received with no stored write data");
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
