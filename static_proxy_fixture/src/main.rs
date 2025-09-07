use libc::c_ulong;
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
    thread::sleep,
    time::Duration,
};

// Constant from linux/i2c-dev.h used to select the target I²C slave.
const I2C_SLAVE: c_ulong = 0x0703;

// Path to the pseudo TTY created by the static proxy library's `socat`
// helper. This must match the `SOCAT_TTY_PATH` macro in the C library.
const SOCAT_TTY_PATH: &str = "/dev/ttyS22";

/// Minimal test fixture demonstrating how the static proxy library forwards
/// I²C traffic through a Unix domain socket. The program performs the
/// following operations:
/// 1. Open an I²C device supplied on the command line (default `/dev/i2c-1`).
/// 2. Issue an `ioctl` to select an arbitrary slave address so the kernel
///    permits transfers.
/// 3. Write the fixed four byte payload `0xDEADBEEF` to the device. When the
///    library is preloaded this traffic is redirected through the proxy
///    socket.
/// 4. Attach to the socat-created pseudo TTY and read back the forwarded
///    bytes, printing them as ASCII hexadecimal for easy inspection.
fn main() -> std::io::Result<()> {
    // Determine the I²C device path from the first command line argument or
    // fall back to `/dev/i2c-1` which is commonly present on Linux systems.
    let args: Vec<String> = env::args().collect();
    let dev_path = args.get(1).map(String::as_str).unwrap_or("/dev/i2c-1");

    // Open the target I²C device for both reading and writing. The proxy
    // library intercepts this call and begins monitoring the descriptor.
    let mut i2c = OpenOptions::new().read(true).write(true).open(dev_path)?;

    // Select a slave address so that subsequent writes are accepted by the
    // kernel. The actual value is irrelevant for the proxy because the data is
    // forwarded unmodified.
    unsafe {
        if libc::ioctl(i2c.as_raw_fd(), I2C_SLAVE, 0x50 as c_ulong) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Encode the payload 0xDEADBEEF as big-endian bytes. Using a fixed value
    // makes it easy to verify that the traffic traversed the proxy correctly.
    let payload: [u8; 4] = 0xDEADBEEF_u32.to_be_bytes();

    // Transmit the bytes to the I²C descriptor. Once redirected by the proxy
    // they will be forwarded to the socat bridge.
    i2c.write_all(&payload)?;

    // Give the helper process a moment to deliver the data to the pseudo TTY
    // before attempting to read it. This avoids racing with the asynchronous
    // forwarding logic.
    sleep(Duration::from_millis(50));

    // Open the pseudo TTY exposed by socat and read back the forwarded data.
    let mut tty = OpenOptions::new().read(true).open(SOCAT_TTY_PATH)?;
    let mut buf = [0u8; 4];
    tty.read_exact(&mut buf)?;

    // Render the received bytes as a continuous hexadecimal string so tests
    // can assert on the exact values without worrying about formatting.
    let hex: String = buf.iter().map(|b| format!("{:02X}", b)).collect();
    println!("{}", hex);

    Ok(())
}
