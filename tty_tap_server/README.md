# tty_tap_server

Simple serial tap server that waits for `/dev/ttyS22` to become available and
processes raw `[addr][cmd][len][data...]` frames produced by the `i2c_redirect`
library. Write frames are logged in hexadecimal, while read frames cause the
server to log the request and return an incrementing counter truncated or
padded to the requested length.
