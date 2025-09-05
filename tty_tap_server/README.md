# tty_tap_server

Simple serial tap server that waits for `/dev/ttyS22` to become available and
processes JSON lines produced by the `i2c_redirect` library. For each `write`
event the hexadecimal payload is decoded, logged as a timestamp, and echoed
back followed by an incrementing counter encoded as another eight bytes.

When the environment variable `I2C_PROXY_RAW` is set to a non-zero value the
server switches to raw mode. In this mode serial traffic is expected to be in
the binary `[addr][cmd][len][data...]` frame format. Each received frame is
printed as a hexadecimal string and echoed back to the serial device unchanged.
