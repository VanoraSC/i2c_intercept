use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::process::Command;
use std::thread;
use std::time::Duration;

use nix::fcntl::OFlag;
use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};
use nix::sys::termios::{self, SetArg};

/// Spawn the tap server and ensure that each read returns the bytes written plus
/// an incrementing counter. Multiple write/read cycles are performed to confirm
/// the counter monotonically increases across reads.
#[test]
fn echoes_with_counter() -> std::io::Result<()> {
    // Create a new pseudo terminal pair. The slave end will be exposed as
    // `/dev/ttyS22` so the server can open it like a real serial port while the
    // test writes to and reads from the master end.
    let master = posix_openpt(OFlag::O_RDWR).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let slave_path = ptsname_r(&master).unwrap();
    let _ = fs::remove_file("/dev/ttyS22");
    symlink(&slave_path, "/dev/ttyS22").unwrap();

    // Put the master end into raw mode so bytes we write are not echoed back
    // to our reader.
    let mut term = termios::tcgetattr(master.as_raw_fd()).unwrap();
    termios::cfmakeraw(&mut term);
    termios::tcsetattr(master.as_raw_fd(), SetArg::TCSANOW, &term).unwrap();

    // Launch the server binary. `CARGO_BIN_EXE_tty_tap_server` points to the
    // built executable in the target directory.
    let mut server = Command::new(env!("CARGO_BIN_EXE_tty_tap_server")).spawn()?;

    // Give the server a moment to open the pseudo terminal before we start
    // sending traffic.
    thread::sleep(Duration::from_millis(100));

    // Interact with the master side of the PTY. Wrapping the file descriptor in
    // a `File` provides convenient `Read` and `Write` implementations.
    let mut tty = unsafe { File::from_raw_fd(master.into_raw_fd()) };

    for i in 0u64..3 {
        // Prepare a short payload unique to each iteration.
        let payload = vec![i as u8 + 1, i as u8 + 2];
        let hex: String = payload.iter().map(|b| format!("{:02x}", b)).collect();

        // Inform the server of the bytes being "written" by the I²C client.
        writeln!(tty, "{{\"type\":\"write\",\"data_hex\":\"{}\"}}", hex)?;

        // Request the same number of bytes back plus eight for the counter.
        let req_len = payload.len() + 8;
        writeln!(tty, "{{\"type\":\"read\",\"len\":{}}}", req_len)?;
        tty.flush()?;

        // The response should contain the original payload followed by the
        // little-endian counter value.
        let mut buf = vec![0u8; req_len];
        tty.read_exact(&mut buf)?;
        let (echo, counter_bytes) = buf.split_at(payload.len());
        assert_eq!(echo, payload.as_slice());
        let counter = u64::from_le_bytes(counter_bytes.try_into().unwrap());
        assert_eq!(counter, i);
    }

    // Terminate the server and clean up the pseudo device.
    let _ = server.kill();
    let _ = server.wait();
    fs::remove_file("/dev/ttyS22").unwrap();

    Ok(())
}
