# I²C Redirect Preload Library (Unix socket client)

Build:
```bash
make
# or: gcc -shared -fPIC -O2 -Wall -Wextra -o libi2c_redirect.so i2c_redirect.c -ldl
```

Cross-compile for aarch64 (requires `aarch64-linux-gnu-gcc` on PATH):
```bash
make CROSS_COMPILE=aarch64-linux-gnu-
```

Run:
```bash
export I2C_PROXY_SOCK=/tmp/i2c.tap.sock
export LD_PRELOAD=$PWD/libi2c_redirect.so
your_i2c_program
```

### Data format

The library always emits binary `[addr][cmd][len][data...]` frames. Tools
consuming the stream must interpret the framing accordingly.

### Optional serial forwarding via socat

The library can automatically spawn a `socat` process that bridges the proxy
socket to a serial TTY.  The helper is executed from the fixed path
`/media/data/socat`, so ensure the binary is available there.  Set
`I2C_SOCAT_TTY` to the device path and point `I2C_PROXY_SOCK` at the same Unix
socket used by the helper:

```bash
export I2C_SOCAT_TTY=/dev/ttyS22            # serial device to bridge
export I2C_SOCAT_SOCKET=/tmp/ttyS22.tap.sock   # optional, defaults to /tmp/ttyS22.tap.sock
export I2C_PROXY_SOCK=$I2C_SOCAT_SOCKET     # socket used by the preload library
export LD_PRELOAD=$PWD/libi2c_redirect.so
your_i2c_program
```

When the host process exits the preload library terminates the `socat`
helper automatically.
