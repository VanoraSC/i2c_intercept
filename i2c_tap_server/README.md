# i2c_tap_server (Unix socket listener)

Build:
```bash
cd i2c_tap_server
cargo build --release
```

Run:
```bash
./target/release/i2c_tap_server /tmp/i2c.tap.sock
# or: I2C_PROXY_SOCK=/tmp/i2c.tap.sock ./target/release/i2c_tap_server
```

Then run your I²C app with LD_PRELOAD + the C library.
