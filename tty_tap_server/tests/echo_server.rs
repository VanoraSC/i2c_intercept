//! Integration test for the TCP echo server.
//!
//! The test spins up the server using an ephemeral port, connects using a
//! standard library `TcpStream` and verifies that a newline-terminated message is
//! echoed back unchanged.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use tty_tap_server::start_echo_server;

/// Helper used to repeatedly attempt connections while the server thread is
/// starting.
fn connect_with_retry(addr: std::net::SocketAddr) -> TcpStream {
    for _ in 0..50 {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }

    panic!("failed to connect to {} after multiple retries", addr);
}

#[test]
fn echoes_a_single_line() {
    // Start the echo server on an ephemeral port.
    let mut server = start_echo_server("127.0.0.1:0").expect("failed to launch server");
    let addr = server.local_addr();

    // Establish the client connection, allowing the server time to begin
    // accepting connections.
    let mut stream = connect_with_retry(addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("failed to configure read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("failed to configure write timeout");

    // Send the newline-terminated payload required by the specification.
    stream
        .write_all(b"hello server\n")
        .expect("failed to send test payload");
    stream.flush().expect("failed to flush payload");

    // Read the echoed response and ensure it matches the transmitted line.
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .expect("failed to read echoed response");
    assert_eq!(response, "hello server\n");

    // Explicitly drop the reader to close the TCP connection, allowing the
    // server's reader thread to observe the disconnect and exit cleanly.
    drop(reader);

    // Shut the server down to reclaim the background listener thread.
    server.shutdown();
}
