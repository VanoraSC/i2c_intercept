use libc::{c_ulong, pollfd, F_GETFL, F_SETFL, O_NONBLOCK, POLLIN};
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, trace, warn};

// Ioctl constants from linux/i2c-dev.h used to configure and communicate with
// the virtual I²C device provided by the preload library.
const I2C_SLAVE: c_ulong = 0x0703;
const I2C_RDWR: c_ulong = 0x0707;
const I2C_M_RD: u16 = 0x0001;

// Structures mirrored from the kernel headers so a read transaction can be
// issued via the I2C_RDWR ioctl. Only the fields required for this simple use
// case are included.
#[repr(C)]
struct I2cMsg {
    addr: u16,
    flags: u16,
    len: u16,
    buf: *mut u8,
}

#[repr(C)]
struct I2cRdwrIoctlData {
    msgs: *mut I2cMsg,
    nmsgs: u32,
}

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
    // and then issues a read request for eight bytes. The tap server logs the
    // write in human readable form and replies to the read with a little-endian
    // `u64` counter. Using binary framing keeps the protocol compact while still
    // allowing the client to verify communication progress.
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

        // Immediately issue an I²C read command requesting eight bytes. The
        // preload library forwards this as a raw read frame to the tap server,
        // which responds with a binary counter value.
        let mut read_buf = [0u8; 8];
        let mut msg = I2cMsg {
            addr,
            flags: I2C_M_RD,
            len: read_buf.len() as u16,
            buf: read_buf.as_mut_ptr(),
        };
        let mut rdwr = I2cRdwrIoctlData {
            msgs: &mut msg,
            nmsgs: 1,
        };
        unsafe {
            libc::ioctl(fd, I2C_RDWR, &mut rdwr);
        }

        // Poll the descriptor and read the expected counter bytes. A timeout is
        // used so the loop continues even if the tap server stops responding.
        let mut resp = [0u8; 8];
        let mut read = 0;
        while read < resp.len() {
            // Wait up to one second for the file descriptor to become readable.
            let mut fds = pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut fds, 1, 1000) };
            if ret == 0 {
                // No data arrived within the timeout window; warn and abandon
                // this iteration so the program does not block indefinitely.
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
            // Interpret the response bytes as a little-endian u64 counter and
            // log the value so callers can monitor progress.
            let counter = u64::from_le_bytes(resp);
            info!("Read counter {}", counter);
        }

        sleep(Duration::from_secs(1));
    }
}
