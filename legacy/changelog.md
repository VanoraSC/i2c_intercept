# I2C Intercept - Changelog

## Version 0.0.7

- Read the full 62-byte response from the TTY before returning data to the caller.
  This prevents leftover bytes from accumulating in the TTY buffer, which would
  eventually misalign subsequent reads and cause failures during long-running
  operations.

## Version 0.0.6

- Fix I2C_INTERCEPT_ADDR_BYPASS feature, and it is now fully functional.

## Version 0.0.5

- Added experimental feature for bypassing specific I2C addresses.
  - Introduced the `I2C_INTERCEPT_ADDR_BYPASS` environment variable.
  - If set, the program will not intercept I2C transactions for the specified address.

## Version 0.0.4

- Removed logic for double open of the RWs.
- Fixed destructor attribute extension syntax.
- Updated README.

## Version 0.0.3
- Change TTY port for I2C bus from ttyS20 -> ttyS22

## Version 0.0.2

- Use `open64()` to intercept the opening of `/dev/i2c-2`.
  - This removes the need for i2c-tools / stub kernel module.
  - Enables full Docker portability, as Docker still relies on the host kernel.
- Renamed source files for brevity.
- Made build script cross-compile, and always run from the correct directory.

## Version 0.0.1

- Initial release.
