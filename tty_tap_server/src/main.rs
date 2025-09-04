use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

/// Connect to `/dev/ttyS22`, log received lines, and echo them back with a
/// monotonically increasing counter.
fn main() -> io::Result<()> {
    // Path to the serial port that the server will interact with.
    let path = Path::new("/dev/ttyS22");

    // Open the device for reading and writing. We clone the handle so that the
    // buffered reader does not interfere with writes.
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    let reader = BufReader::new(file.try_clone()?);
    let mut writer = file;

    println!("Listening on {:?}...", path);
    let mut counter: u64 = 0;

    // Process each line received from the device.
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() { continue; }

        println!("Received: {}", line);

        // Prepare a response that includes an incrementing counter and the
        // original data, then send it back to the device.
        let response = format!("{}: {}\n", counter, line);
        writer.write_all(response.as_bytes())?;
        writer.flush()?;
        counter += 1;
    }

    Ok(())
}
