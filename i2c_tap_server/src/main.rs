use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt}; // for from_mode()
use std::path::Path;
use std::thread;
use serde_json::Value;

// Simple utility that accepts connections on a Unix domain socket and prints
// any JSON lines it receives. It is primarily useful for debugging the output
// of the I²C redirect library. When the `I2C_PROXY_RAW` environment variable is
// set the server expects binary `[addr][cmd][len][data...]` frames and dumps
// them in a human readable form.

/// Handle a single client connection by printing each line as JSON.
fn handle_client(stream: UnixStream) -> io::Result<()> {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        println!("[tap] received: {}", line); // trace incoming payload
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => {
                let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
                println!("=== {} ===", typ);
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
                println!();
            }
            Err(_) => println!("(raw) {}", line),
        }
    }
    Ok(())
}

/// Handle a client connection in raw mode. Frames are received in the format
/// `[addr][cmd][len][data...]` where `cmd` is 0 for writes and 1 for reads.
fn handle_client_raw(mut stream: UnixStream) -> io::Result<()> {
    loop {
        let mut hdr = [0u8; 3];
        println!("[tap] waiting for raw header");
        if let Err(e) = stream.read_exact(&mut hdr) {
            // EOF is expected when the client disconnects.
            if e.kind() != io::ErrorKind::UnexpectedEof { return Err(e); }
            println!("[tap] client closed connection");
            break;
        }
        let addr = hdr[0];
        let cmd = hdr[1];
        let len = hdr[2] as usize;
        let mut data = vec![0u8; len];
        if let Err(e) = stream.read_exact(&mut data) {
            return Err(e);
        }
        let dir = if cmd == 0 { "write" } else { "read" };
        let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
        println!("{} addr=0x{:02x} len={} data={}", dir, addr, len, hex);
    }
    Ok(())
}

fn main() -> io::Result<()> {
    // Determine socket path from CLI arg or environment.
    let sock_path = env::args().nth(1)
        .or_else(|| env::var("I2C_PROXY_SOCK").ok())
        .unwrap_or_else(|| "/tmp/i2c.tap.sock".into());

    // Toggle raw mode via environment variable. When set, the server expects
    // binary frames instead of JSON lines.
    let raw_mode = env::var("I2C_PROXY_RAW").map_or(false, |v| v != "0");

    // Remove any stale socket path to avoid bind errors.
    let p = Path::new(&sock_path);
    if p.exists() {
        let md = fs::symlink_metadata(&p)?;
        if md.file_type().is_socket() || md.is_file() { fs::remove_file(&p)?; }
    }

    let listener = UnixListener::bind(&sock_path)?;
    // Make sure others can connect (optional: set perms)
    let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o666));

    println!("Listening on {}", sock_path);

    // Accept connections and spawn a thread to handle each using the
    // appropriate parsing mode.
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                println!("Accepted new connection");
                let is_raw = raw_mode;
                thread::spawn(move || {
                    let result = if is_raw {
                        handle_client_raw(stream)
                    } else {
                        handle_client(stream)
                    };
                    if let Err(e) = result {
                        eprintln!("client error: {}", e);
                    }
                    println!("Client handler exiting");
                });
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
    // unreachable in normal flow
    Ok(())
}
