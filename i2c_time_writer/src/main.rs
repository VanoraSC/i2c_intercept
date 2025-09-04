use libc::c_ulong;
use std::{
    env,
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// Constant from linux/i2c-dev.h used to select the target I²C slave.
const I2C_SLAVE: c_ulong = 0x0703;

// Periodically write the current UNIX time to the specified I²C device
// address. The timestamp is transmitted as a newline-terminated ASCII string
// so the companion tap server can easily echo and display the value without
// dealing with byte order or binary parsing.
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

    // Open the I²C device and select the slave address. The file handle is
    // cloned so that reads can be buffered independently from writes without
    // disturbing the underlying seek position.
    let file = OpenOptions::new().read(true).write(true).open(dev_path)?;
    let fd = file.as_raw_fd();
    unsafe {
        if libc::ioctl(fd, I2C_SLAVE, addr as c_ulong) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let mut reader = BufReader::new(file.try_clone()?);
    let mut writer = file;

    // Every second, write the current timestamp to the device and then read
    // back a line of text. The companion tap server echoes the write and
    // prefixes the original data with a monotonically increasing counter in the
    // form "<counter>: <value>". Parsing this response allows us to verify both
    // the data integrity and observe the counter for debugging purposes.
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let secs = now.as_secs();

        // Format the current time as a newline-terminated ASCII string. Using
        // text keeps the data human readable when inspecting logs and avoids
        // endianness concerns on different architectures.
        let line = format!("{}\n", secs);

        // Write the textual timestamp to the I²C device. `write_all` blocks
        // until the entire buffer has been transmitted so the reader sees a
        // complete line. Flushing prevents the data from lingering in userland
        // buffers.
        writer.write_all(line.as_bytes())?;
        writer.flush()?;

        // Block until a newline-terminated response is received. This ensures
        // a strict request/response exchange so that no more than one
        // timestamp is in flight at any given time.
        let mut text = String::new();
        match reader.read_line(&mut text) {
            Ok(0) => {
                eprintln!("no data available from device");
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("read error: {}", e);
                continue;
            }
        }
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
