# I²C Redirect Preload Library (Unix socket client)

Build:
```bash
make
# or: gcc -shared -fPIC -O2 -Wall -Wextra -o libi2c_redirect.so i2c_redirect.c -ldl
```

Run (tee mode):
```bash
export I2C_PROXY_SOCK=/tmp/i2c.tap.sock
export I2C_PROXY_PASSTHROUGH=1
export LD_PRELOAD=$PWD/libi2c_redirect.so
your_i2c_program
```

Run (redirect only, no real hardware access):
```bash
export I2C_PROXY_SOCK=/tmp/i2c.tap.sock
unset I2C_PROXY_PASSTHROUGH
export LD_PRELOAD=$PWD/libi2c_redirect.so
your_i2c_program
```
