use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt}; // for from_mode()
use std::path::Path;
use std::thread;
use serde_json::Value;

// Simple utility that accepts connections on a Unix domain socket and prints
// any JSON lines it receives. It is primarily useful for debugging the output
// of the I²C redirect library.

/// Handle a single client connection by printing each line as JSON.
fn handle_client(stream: UnixStream) -> io::Result<()> {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
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

fn main() -> io::Result<()> {
    // Determine socket path from CLI arg or environment.
    let sock_path = env::args().nth(1)
        .or_else(|| env::var("I2C_PROXY_SOCK").ok())
        .unwrap_or_else(|| "/tmp/i2c.tap.sock".into());

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

    // Accept connections and spawn a thread to handle each.
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream) {
                        eprintln!("client error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
    // unreachable in normal flow
    Ok(())
}
