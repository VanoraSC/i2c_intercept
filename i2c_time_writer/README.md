# i2c_time_writer

Example program that writes the current Unix time to an I²C device once per second.
The program is intended to be used with the `libi2c_redirect.so` preload library so
that all I²C operations are intercepted and logged.

## Build

```bash
cd i2c_time_writer
cargo build --release
```

## Run

```bash
LD_PRELOAD=../c_preload_lib/libi2c_redirect.so ./target/release/i2c_time_writer /dev/i2c-1 0x50
```

The first argument is the path to the I²C device, and the second is the 7-bit
hexadecimal device address. The program writes the current time in big-endian
seconds since the Unix epoch every second.
