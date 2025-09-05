# tty_tap_server

Simple serial tap server that waits for `/dev/ttyS22` to become available and
processes JSON lines produced by the `i2c_redirect` library. Payload bytes from
`write` events are stored and later echoed back verbatim when a `read` event is
received. If multiple reads occur without an intervening write, the most recent
data is returned each time.

When the environment variable `I2C_PROXY_RAW` is set to a non-zero value the
server switches to raw mode. In this mode serial traffic is expected to be in
the binary `[addr][cmd][len][data...]` frame format. Each received frame is
printed as a hexadecimal string and echoed back to the serial device unchanged.
