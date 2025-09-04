use libc::c_ulong;
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// Constant from linux/i2c-dev.h used to select the target I²C slave.
const I2C_SLAVE: c_ulong = 0x0703;

// Periodically write the current UNIX time to the specified I²C device
// address. The timestamp is transmitted as a little-endian `u64` so the
// companion tap server can interpret the binary value directly. Using the raw
// representation avoids the overhead of formatting ASCII strings and matches
// the expectation of consumers that operate on native integers.
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <i2c-dev-path> <addr>", args[0]);
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

    // Open the I²C device and select the slave address.
    let mut file = OpenOptions::new().read(true).write(true).open(dev_path)?;
    let fd = file.as_raw_fd();
    unsafe {
        if libc::ioctl(fd, I2C_SLAVE, addr as c_ulong) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Every second, write the current timestamp to the device and then read
    // back a line of text. The companion tap server echoes the write and
    // prefixes the original data with a monotonically increasing counter in the
    // form "<counter>: <value>". Parsing this response allows us to verify both
    // the data integrity and observe the counter for debugging purposes.
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let secs = now.as_secs();

        // Encode the current time as a little-endian byte array. Sending the
        // raw bytes keeps the wire format compact and unambiguous.
        let bytes = secs.to_le_bytes();

        // Write the 8-byte timestamp to the I²C device. `write_all` blocks until
        // all bytes have been transmitted so the reader sees a complete value.
        file.write_all(&bytes)?;

        // Collect bytes from the device until a newline terminator is seen.
        // The response is expected to be ASCII and follow the pattern
        // "<counter>: <value>". Reading byte by byte keeps the logic simple and
        // avoids buffering more than necessary.
        let mut raw = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            // Attempt to read a single byte from the I²C device. Using
            // `read` instead of `read_exact` lets us gracefully handle short
            // reads or transient I/O errors without terminating the program.
            match file.read(&mut byte) {
                // A return of zero can mean two different things depending on
                // when it occurs. If no data has been received yet it likely
                // indicates that the tap server has not responded and we
                // should give up for this iteration. However, if some bytes
                // were already read it simply means more data has not yet
                // arrived. In that case wait briefly and try again so that
                // the partially received line can be completed instead of
                // being interpreted as an empty value.
                Ok(0) => {
                    if raw.is_empty() {
                        eprintln!("no data available from device");
                        break;
                    } else {
                        sleep(Duration::from_millis(10));
                        continue;
                    }
                }
                // Successfully read a byte; accumulate it unless it terminates
                // the line. Guard against excessively long responses as before.
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    raw.push(byte[0]);
                    if raw.len() > 128 {
                        break;
                    }
                }
                // Any error is reported but does not abort the entire program,
                // allowing the writer to continue operating even if a single
                // read fails.
                Err(e) => {
                    eprintln!("read error: {}", e);
                    break;
                }
            }
        }

        let text = String::from_utf8_lossy(&raw);
        if let Some((ctr, val)) = text.split_once(':') {
            let counter = ctr.trim().parse::<u64>().unwrap_or(0);
            let echoed = val.trim().parse::<u64>().unwrap_or(0);
            println!("Read back: {} (counter {})", echoed, counter);
        } else {
            // If the response does not match the expected format, print the
            // raw string so that developers can inspect the unexpected data.
            println!("Read back (unparsed): {}", text.trim());
        }

        sleep(Duration::from_secs(1));
    }
}
