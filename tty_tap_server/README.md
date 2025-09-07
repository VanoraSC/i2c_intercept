# tty_tap_server

Simple serial tap server that waits for `/dev/ttyS22` to become available and
processes raw `[addr][cmd][len][data...]` frames produced by the `i2c_redirect`
library. For each `write` frame the server logs the hexadecimal representation
and echoes the first eight payload bytes followed by an incrementing counter
encoded as another eight bytes.
