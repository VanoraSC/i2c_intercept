# tty_tap_server

Simple serial tap server that waits for `/dev/ttyS22` to become available and
processes raw `[addr][cmd][d0]...[d7]` frames produced by the `i2c_redirect`
library. Write frames are logged in hexadecimal, while read frames cause the
server to log the request and return a 62-byte response containing an
incrementing counter padded with zeros.
