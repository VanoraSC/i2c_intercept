# i2c_intercept Build Instructions

This repository contains a collection of tools for intercepting and manipulating I²C traffic.  The project includes:

- **c_preload_lib** – a shared library used to intercept I²C operations via LD_PRELOAD
- **tty_tap_server** – a Rust server that listens on a serial TTY, logs raw I²C write commands and fulfills read requests with a counter value
- **i2c_time_writer** – a Rust utility that periodically writes the current time and issues matching read requests

## Building

The top-level `Makefile` builds all components in one step.  From the repository root run:

```bash
make
```

This compiles the C preload library and the Rust utilities `tty_tap_server` and `i2c_time_writer`.

### Cross-compiling for aarch64

To target 64-bit ARM systems, pass `ARCH=aarch64`:

```bash
make ARCH=aarch64
```

This configures the appropriate `aarch64-linux-gnu-` cross compiler and Rust target.  An aarch64 cross toolchain and the Rust target `aarch64-unknown-linux-gnu` must be installed on your system.

You can override the toolchain manually by setting `CROSS_COMPILE` or `RUST_TARGET` variables when invoking `make`.

### Cleaning

Remove build artifacts with:

```bash
make clean
```

## Serial forwarding with socat

When using the `c_preload_lib` you can have it automatically start a
`socat` process that bridges a Unix domain socket to a serial TTY. The helper
is invoked from `/media/data/socat`, so that binary must be present. Configure
the following environment variables before launching the target application:

* `I2C_SOCAT_TTY` – path of the serial device (default: `/dev/ttyS22`).
* `I2C_SOCAT_SOCKET` – Unix socket path for the `socat` listener (default:
  `/tmp/ttyS22.tap.sock`).
* `I2C_PROXY_SOCK` – socket the preload library connects to (default:
  `/tmp/ttyS22.tap.sock`).
* `I2C_REDIRECT_EXEMPT` – comma separated list of I²C addresses that should
  bypass the redirect and access hardware directly. Addresses may be given in
  decimal or prefixed with `0x` for hexadecimal.

These variables are optional; the preload library uses the defaults when they
are unset. The helper process is automatically terminated when the library is
unloaded.

## Testing with `tty_tap_server` and `i2c_time_writer`

After building, you can verify the end‑to‑end flow by running the tap server and
time writer together. In one terminal start the server which listens on the
serial device `/dev/ttyS22`:

```bash
./tty_tap_server/target/release/tty_tap_server
```

In a second terminal run the time writer with the preload library:

```bash
LD_PRELOAD=./c_preload_lib/libi2c_redirect.so \
./i2c_time_writer/target/release/i2c_time_writer /dev/i2c-1 0x50
```

The time writer sends the current Unix timestamp once per second as an
eight-byte little-endian value and then issues an I²C read command requesting
sixty-two bytes. The tap server logs the write, records the read request and
responds with a little-endian counter padded with zeros. The time writer prints
the returned counter to its standard output. Override `I2C_SOCAT_TTY`,
`I2C_SOCAT_SOCKET` or `I2C_PROXY_SOCK` if different paths are needed.

