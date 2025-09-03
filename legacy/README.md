# I2C INTERCEPT

This library intercepts I2C file operations from a process and redirects them to
a TTY.

## Usage

To use this library, you simply need to compile it and then preload it into your
program using the `LD_PRELOAD` environment variable.

```bash
LD_PRELOAD=/absolute/path/to/i2c_intercept.so ./your_program
```

You can also bypass specific I2C addresses by setting the `I2C_INTERCEPT_ADDR_BYPASS` environment variable to a comma-separated list of addresses. For example:

```bash
export I2C_INTERCEPT_ADDR_BYPASS=0x30,52
LD_PRELOAD=/absolute/path/to/i2c_intercept.so ./your_program
```

To (cross-)compile, use the provided build script:

```bash
./build.sh
```

## Implementing the TTY-side

If you are implementing the TTY-side of the I2C communication, you need to
handle the messages that this library sends over the TTY. The library formats
the messages to include the I2C address and command type, which allows you to
distinguish between read and write operations.

The message format is as follows:

```text
I2C address:  1 byte   (the I2C address of the device)
Command type: 1 byte,  (0 for write, 1 for read)
Data:         N bytes, (the actual data being written)
```

If you receive a message with the command type set to 1, it indicates a read
operation, and it will contain 8 bytes of zeros as the data. You should
immediately respond with the data that the I2C device would return for that read
operation, as the communication is half-duplex; there is a lock on the device
from when the operation is initiated until the response is sent back.

Reads operations have a timeout of 1 second, and expect a minimum of 62 bytes.
The 62 bytes is specific for the Umbra Slice I2C protocol this library is
designed for, as is the 8 bytes of zeros for the read operation.

## How it works

The library intercepts low-level file operations on the I2C device by overriding
the following functions:

- `open64`
- `close`
- `write`
- `read`
- `ioctl`

How the interception works:

- We override the original function signatures, and use `dlsym` to get the
  original implementations of the functions we want to intercept.
- In the function bodies, we check if the parameters' pathname or file
  descriptors match the I2C device path or file descriptor we want to intercept.
- If they do, we handle the call ourselves, otherwise we call the original
  implementation using `dlsym`.

Note that we don't get to choose the parameters for these functions, as we must
match the original function signatures. This necessitates the use of some static
variables to manage our logic, such as the file descriptor and the I2C address.

## Limitations

- This library only works for I2C communication via the standard file system
  read and write functions. It does not support ioctl RDWR or SMBUS. Link to
  relevant [stack overflow discussion](https://stackoverflow.com/a/38382649).
  - Our current system does not use these other features, and they are not
    trivial to implement.
- For bypassed addresses, only the
  [I2C_SLAVE and I2C_SLAVE_FORCE](https://github.com/spotify/linux/blob/master/include/linux/i2c-dev.h)
  ioctl requests are bypassed. Other requests will still be intercepted.
  - This is due how the Linux kernel handles ioctl requests. We cannot handle
    ioctl requests made before knowing what the I2C address is for a given file
    descriptor, and trying to replay these requests is not feasible.
- The library is hardcoded to intercept `/dev/i2c-2` and redirect to
  `/dev/ttyS22`. You can modify these paths in the `util.c` file.
  - May be made configurable in the future.
- The library requires a specific message format for the TTY-side
  implementation, which may not be compatible with all I2C devices.
  - May be made more generic in the future, but currently tailored for the Umbra
    Slice I2C protocol.
