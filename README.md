# i2c_intercept Build Instructions

This repository contains a collection of tools for intercepting and manipulating I²C traffic.  The project includes:

- **c_preload_lib** – a shared library used to intercept I²C operations via LD_PRELOAD
- **i2c_tty_redirect** – a helper that forwards I²C data to a serial port
- **i2c_tap_server** – a Rust server that streams captured bus data
- **i2c_time_writer** – a Rust utility that inserts timing information into the I²C stream

## Building

The top-level `Makefile` builds all components in one step.  From the repository root run:

```bash
make
```

This compiles the C preload library, `i2c_tty_redirect`, and both Rust utilities.

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
`socat` process that bridges a Unix domain socket to a serial TTY. Configure
the following environment variables before launching the target application:

* `I2C_SOCAT_TTY` – path of the serial device (e.g. `/dev/ttyS22`).
* `I2C_SOCAT_SOCKET` – Unix socket path for the `socat` listener. Defaults to
  `/tmp/ttyS22.tap.sock` if unset.

Set `I2C_PROXY_SOCK` to the same socket so the preload library connects to the
bridge. The helper process is automatically terminated when the library is
unloaded.

