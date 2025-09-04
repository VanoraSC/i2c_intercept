# tty_tap_server

Simple serial tap server that waits for `/dev/ttyS22` to become available,
prints any lines received, and echoes each line back with an incrementing
counter.

When the environment variable `I2C_PROXY_RAW` is set to a non-zero value the
server switches to raw mode. In this mode serial traffic is expected to be in
the binary `[addr][cmd][len][data...]` frame format. Each received frame is
printed as a hexadecimal string and echoed back to the serial device
unchanged.
