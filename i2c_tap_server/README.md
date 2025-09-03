# i2c_tap_server (Unix socket listener)

Build:
```bash
cd i2c_tap_server
cargo build --release
```

Cross-compile for aarch64 (requires Rust target and linker):
```bash
cd i2c_tap_server
rustup target add aarch64-unknown-linux-gnu # once
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build --release --target aarch64-unknown-linux-gnu
```

Run:
```bash
./target/release/i2c_tap_server /tmp/i2c.tap.sock
# or: I2C_PROXY_SOCK=/tmp/i2c.tap.sock ./target/release/i2c_tap_server
```

Then run your I²C app with LD_PRELOAD + the C library.
