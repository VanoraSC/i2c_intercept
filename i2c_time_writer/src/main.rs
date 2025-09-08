// Only the constants required for configuring the file descriptor and
// issuing I²C ioctls are imported from `libc`.  The previous version of the
// program polled the descriptor explicitly, but the preload library now
// manages timeouts internally so the polling types are no longer needed.
use libc::{c_ulong, F_GETFL, F_SETFL, O_NONBLOCK};
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, trace, warn};

// Ioctl constant from linux/i2c-dev.h used to select the slave address for
// subsequent transfers on the virtual I²C device provided by the preload
// library.
const I2C_SLAVE: c_ulong = 0x0703;

// Periodically write the current UNIX time to the specified I²C device
// address. The timestamp is transmitted as a little-endian `u64` so the
// companion tap server can interpret the binary value directly. Using the raw
// representation avoids the overhead of formatting ASCII strings and matches
// the expectation of consumers that operate on native integers.
fn main() -> std::io::Result<()> {
    // Initialize tracing so that all subsequent operations emit detailed logs.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        error!("Usage: {} <i2c-dev-path> <addr>", args[0]);
        std::process::exit(1);
    }

    // Parse device path and address from arguments.
    let dev_path = &args[1];
    let addr = if let Some(stripped) = args[2].strip_prefix("0x") {
        u16::from_str_radix(stripped, 16)
    } else {
        args[2].parse()
    }
    .expect("invalid address");
    trace!("using device {} addr=0x{:x}", dev_path, addr);

    // Open the I²C device and select the slave address.
    let mut file = OpenOptions::new().read(true).write(true).open(dev_path)?;
    let fd = file.as_raw_fd();
    unsafe {
        if libc::ioctl(fd, I2C_SLAVE, addr as c_ulong) < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Place the file descriptor into non-blocking mode so reads can use a
        // timeout. This prevents the process from hanging indefinitely if the
        // tap server stops responding.
        let flags = libc::fcntl(fd, F_GETFL, 0);
        if libc::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Drain any bytes that might remain in the proxy socket from a previous
    // run. Leaving stale frames in the buffer would cause the first iteration
    // of the loop below to process outdated data, so the entire available
    // buffer is read and discarded before proceeding.
    let mut discard = [0u8; 64];
    loop {
        match file.read(&mut discard) {
            Ok(0) => break, // No more data to drain.
            Ok(_) => continue, // Keep reading until the buffer is empty.
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    // Every second the program writes the current timestamp to the I²C device
    // and then issues a read request for sixty-two bytes. The tap server logs
    // the write in human readable form and replies to the read with a
    // little-endian `u64` counter padded with zeros. Using binary framing keeps
    // the protocol compact while still allowing the client to verify
    // communication progress.
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let secs = now.as_secs();

        // Encode the current time as a little-endian byte array. Sending the
        // raw bytes keeps the wire format compact and unambiguous.
        let bytes = secs.to_le_bytes();

        // Write the 8-byte timestamp to the I²C device. `write_all` blocks until
        // all bytes have been transmitted so the reader sees a complete value.
        trace!("wrote timestamp {}", secs);
        file.write_all(&bytes)?;

        // Immediately read sixty-two bytes from the device. The preload
        // library transforms this call into the requisite read command on the
        // proxy socket and waits for a fixed-size response. A return value of
        // zero indicates that the tap server failed to provide data within its
        // 100 ms timeout window.
        let mut resp = [0u8; 62];
        match file.read(&mut resp) {
            Ok(n) if n == resp.len() => {
                // The response begins with an eight-byte little-endian counter
                // maintained by the tap server. Display it so callers can
                // observe progress.
                let mut ctr_bytes = [0u8; 8];
                ctr_bytes.copy_from_slice(&resp[..8]);
                let counter = u64::from_le_bytes(ctr_bytes);
                info!("Read counter {}", counter);
            }
            Ok(0) => {
                // A zero-length read signals that no data was available within
                // the timeout period enforced by the preload library.
                warn!("timed out waiting for response");
            }
            Ok(n) => {
                // Any other byte count is unexpected because the protocol always
                // delivers exactly sixty-two bytes.
                warn!(
                    "short read: expected {} bytes, received {}",
                    resp.len(),
                    n
                );
            }
            Err(e) => {
                // Propagate I/O errors so the caller is aware of problems
                // interacting with the device.
                error!("read error: {}", e);
            }
        }

        sleep(Duration::from_secs(1));
    }
}
