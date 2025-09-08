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
export LD_PRELOAD=$PWD/libi2c_redirect.so
your_i2c_program
```

The library consults several environment variables but falls back to sensible
defaults when they are unset:

- `I2C_PROXY_SOCK` – Unix socket used to communicate with the tap server
  (default: `/tmp/ttyS22.tap.sock`)
- `I2C_SOCAT_TTY` – serial device bridged by the helper (default: `/dev/ttyS22`)
- `I2C_SOCAT_SOCKET` – socket path used by the `socat` helper (default:
  `/tmp/ttyS22.tap.sock`)
- `I2C_REDIRECT_EXEMPT` – comma separated list of I²C addresses that should
  bypass the redirect and talk to hardware directly (default: none). Addresses
  may be given in decimal or prefixed with `0x` for hexadecimal.

### Data format

The library always emits fixed-size ten-byte frames formatted as
`[addr][cmd][d0]...[d7]`. The `cmd` byte is `0` for write operations and
`READ_COMMAND` for read requests. Write frames transmit the eight data bytes
verbatim so consumers can observe the payload. Read frames ignore the data
section (which is typically all zeros) and cause the tap server to return a
62-byte response.

### Optional serial forwarding via socat

The library can automatically spawn a `socat` process that bridges the proxy
socket to a serial TTY.  The helper is executed from the fixed path
`/media/data/socat`, so ensure the binary is available there.  Set
`I2C_SOCAT_TTY` to the device path and point `I2C_PROXY_SOCK` at the same Unix
socket used by the helper:

```bash
# The following exports are optional; the shown values are the defaults.
export I2C_SOCAT_TTY=/dev/ttyS22
export I2C_SOCAT_SOCKET=/tmp/ttyS22.tap.sock
export LD_PRELOAD=$PWD/libi2c_redirect.so
your_i2c_program
```

When the host process exits the preload library terminates the `socat`
helper automatically.
