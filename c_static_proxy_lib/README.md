# Static I²C Socket Proxy Library

This library provides an LD_PRELOAD shim that intercepts I²C bus operations
and forwards them to a Unix domain socket.  The socket can be bridged to a
synthetic UART device using `socat`, allowing traffic to be observed or
emulated without modifying the original application.

Unlike the original preload library this implementation is configured entirely
through compile-time constants.  Change the definitions in
`i2c_static_proxy.c` or override them via compiler flags to adjust the socket
location, the helper binary path, or the synthetic TTY name.

## Build

```bash
make
# or: gcc -shared -fPIC -O2 -Wall -Wextra -o libi2c_static_proxy.so i2c_static_proxy.c -ldl
```

## Usage

1. Compile the library.
2. Preload it before running an I²C aware program:

```bash
export LD_PRELOAD=$PWD/libi2c_static_proxy.so
your_i2c_program
```

The library automatically spawns a `socat` instance that bridges the proxy
socket to the configured pseudo terminal.  Reads and writes performed by the
intercepted program travel across this connection unchanged, enabling
bidirectional communication with external tools.
