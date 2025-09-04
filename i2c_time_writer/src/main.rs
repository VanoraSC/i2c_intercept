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
        file.write_all(&bytes)?;

        // The tap server responds with the same eight bytes followed by an
        // additional eight-byte counter. Use `read_exact` so that partial reads
        // are retried until the full 16‑byte packet is received or an error
        // occurs.
        let mut resp = [0u8; 16];
        match file.read_exact(&mut resp) {
            Ok(_) => {
                // Split the response into the echoed timestamp and the counter
                // portion. Converting with `from_le_bytes` yields the native
                // `u64` values for display and further processing.
                let echoed = u64::from_le_bytes(resp[0..8].try_into().unwrap());
                let counter = u64::from_le_bytes(resp[8..16].try_into().unwrap());
                println!("Read back: {} (counter {})", echoed, counter);
            }
            Err(e) => {
                // Report any I/O failure but continue looping so that a transient
                // error does not permanently stop the writer.
                eprintln!("read error: {}", e);
            }
        }

        sleep(Duration::from_secs(1));
    }
}
