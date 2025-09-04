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
// address.  The timestamp is sent as an ASCII decimal string followed by a
// newline so that the line-oriented tap server can parse and echo it.  Using a
// textual representation keeps the example simple and avoids dealing with byte
// order when inspecting logs.
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

        // Format the current time as a newline-terminated ASCII string.  The
        // tap server operates in line mode and expects text, so sending the
        // timestamp in this form ensures the server can parse and echo the
        // value without additional decoding.  The newline also delineates each
        // write operation for both the server and the reader below.
        let line = format!("{}\n", secs);

        // Send the textual timestamp to the I²C device.  `write_all` blocks
        // until the entire buffer is transmitted, guaranteeing the complete
        // line is delivered in one operation.
        file.write_all(line.as_bytes())?;

        // Collect bytes from the device until a newline terminator is seen.
        // The response is expected to be ASCII and follow the pattern
        // "<counter>: <value>". Reading byte by byte keeps the logic simple and
        // avoids buffering more than necessary.
        let mut raw = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            // Read a single byte; if this fails the I²C transaction likely
            // did not produce a response and the error will bubble up.
            file.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            raw.push(byte[0]);
            // Guard against excessively long or malformed responses by
            // capping the buffer size.
            if raw.len() > 128 {
                break;
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
