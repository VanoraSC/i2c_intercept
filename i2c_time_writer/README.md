# i2c_time_writer

Example program that writes the current Unix time to an I²C device once per
second. The timestamp is transmitted as an eight-byte little-endian binary
`u64`, keeping the wire format compact and easy to parse. After each write the
program issues a read request for eight bytes, which the companion tap server
fulfills with its own little-endian counter. The program is intended to be used
with the `libi2c_redirect.so` preload library so that all I²C operations are
intercepted and logged.

## Build

```bash
cd i2c_time_writer
cargo build --release
```

## Run

```bash
LD_PRELOAD=../c_preload_lib/libi2c_redirect.so \
./target/release/i2c_time_writer /dev/i2c-1 0x50
```

The first argument is the path to the I²C device, and the second is the 7-bit
hexadecimal device address. The preload library spawns a `socat` helper (looked
up at `/media/data/socat`) to bridge the proxy socket to the serial device
`/dev/ttyS22` and communicates over `/tmp/ttyS22.tap.sock` by default. Override
`I2C_SOCAT_TTY`, `I2C_SOCAT_SOCKET` or `I2C_PROXY_SOCK` to use different paths.
Start the `tty_tap_server` in another shell and then run the command above. The
utility writes the current time every second, issues a read for eight bytes and
prints the returned counter in decimal when received.
