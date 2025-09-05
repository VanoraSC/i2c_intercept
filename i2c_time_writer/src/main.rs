use libc::{c_ulong, pollfd, F_GETFL, F_SETFL, O_NONBLOCK, POLLIN};
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, trace, warn};

// Constant from linux/i2c-dev.h used to select the target I²C slave.
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

    // Every second the program writes the current timestamp to the I²C device
    // and expects a binary response. The companion tap server echoes the same
    // eight bytes back and appends an additional little-endian `u64` counter.
    // This compact binary protocol avoids the overhead of parsing ASCII text
    // while still allowing the client to verify that the data round-tripped
    // correctly and to observe a monotonically increasing sequence number.
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

        // The tap server responds with the same eight bytes followed by an
        // additional eight-byte counter. Rather than blocking forever waiting
        // for a full 16-byte response, poll the file descriptor with a timeout
        // and read incrementally. This allows the loop to continue even if the
        // tap server becomes unresponsive.
        let mut resp = [0u8; 16];
        let mut read = 0;
        // Record when the response phase began so we can enforce a hard
        // deadline on the read. Without this guard the loop could wait
        // indefinitely if the device never produces data.
        let start = Instant::now();
        while read < resp.len() {
            // If more than 500ms has elapsed with no full response, abandon the
            // read so the main loop can continue and try again on the next
            // iteration.
            let elapsed = start.elapsed();
            if elapsed >= Duration::from_millis(500) {
                warn!("timed out waiting for response");
                break;
            }

            // Wait only for the remaining time before the 500ms deadline for
            // the file descriptor to become readable. This prevents a single
            // poll call from blocking past the overall timeout.
            let remaining = Duration::from_millis(500).saturating_sub(elapsed);
            let mut fds = pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut fds, 1, remaining.as_millis() as i32) };
            if ret == 0 {
                // The device produced no data within the allotted window.
                warn!("timed out waiting for response");
                break;
            } else if ret < 0 {
                // Any polling failure is reported and treated like a timeout.
                error!("poll error: {}", std::io::Error::last_os_error());
                break;
            }

            match file.read(&mut resp[read..]) {
                Ok(0) => {
                    // End-of-file is unexpected for a character device; abort
                    // this iteration so the caller can retry.
                    error!("unexpected EOF from device");
                    break;
                }
                Ok(n) => {
                    // Accumulate the bytes read so far and continue until the
                    // complete response is received.
                    read += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // The device was not actually ready; poll again.
                    continue;
                }
                Err(e) => {
                    // Any other error is reported and the partial read is
                    // discarded so the loop can try again.
                    error!("read error: {}", e);
                    break;
                }
            }
        }

        if read == resp.len() {
            // Split the response into the echoed timestamp and the counter
            // portion. Converting with `from_le_bytes` yields the native
            // `u64` values for display and further processing.
            let echoed = u64::from_le_bytes(resp[0..8].try_into().unwrap());
            let counter = u64::from_le_bytes(resp[8..16].try_into().unwrap());
            info!("Read back: {} (counter {})", echoed, counter);
        }

        sleep(Duration::from_secs(1));
    }
}
