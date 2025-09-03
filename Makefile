# Top-level Makefile to build all components of the i2c_intercept project.
#
# The Makefile orchestrates compilation of the C preload library, the
# i2c_tty_redirect utility and the Rust based tools.  It also exposes a
# simple mechanism for cross compiling to aarch64 by setting `ARCH=aarch64`.
# When cross compiling, an aarch64 cross toolchain and the matching Rust
# target must be installed on the system.

# Optional architecture selection.  By default native tools are used.  When
# ARCH is set to `aarch64` the C compiler prefix and Rust target triple are
# adjusted to target 64-bit ARM systems.
ARCH ?= native

# Default toolchain prefixes which may be overridden by the user.
CROSS_COMPILE ?=
RUST_TARGET ?=

# Automatically configure cross compilation variables when targeting
# aarch64.  Users may still override CROSS_COMPILE or RUST_TARGET explicitly
# if they need a custom setup.
ifeq ($(ARCH),aarch64)
CROSS_COMPILE := aarch64-linux-gnu-
RUST_TARGET := aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER := $(CROSS_COMPILE)gcc
endif

# Derive the C compiler and Rust target flag from the above configuration.
CC := $(CROSS_COMPILE)gcc
CFLAGS ?= -O2 -Wall -Wextra
CARGO_TARGET_FLAG :=
CARGO_ENV :=
ifneq ($(RUST_TARGET),)
CARGO_TARGET_FLAG := --target $(RUST_TARGET)
endif
ifneq ($(CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER),)
CARGO_ENV := CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=$(CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER)
endif

# Phony targets prevent conflicts with files of the same name.
.PHONY: all c_preload_lib i2c_tty_redirect i2c_tap_server i2c_time_writer clean

# Build everything by default.
all: c_preload_lib i2c_tty_redirect i2c_tap_server i2c_time_writer

# Build the C preload library by invoking its own Makefile and forwarding the
# CROSS_COMPILE setting so it can also be cross compiled.
c_preload_lib:
	$(MAKE) -C c_preload_lib CROSS_COMPILE=$(CROSS_COMPILE)

# Compile the i2c_tty_redirect helper which forwards I²C traffic to a serial
# port.  The program uses pthreads so the -pthread flag is required.
i2c_tty_redirect: i2c_tty_redirect.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

# Build the Rust based tap server.
i2c_tap_server:
	$(CARGO_ENV) cargo build $(CARGO_TARGET_FLAG) --manifest-path i2c_tap_server/Cargo.toml

# Build the utility that writes time data into the I²C stream.
i2c_time_writer:
	$(CARGO_ENV) cargo build $(CARGO_TARGET_FLAG) --manifest-path i2c_time_writer/Cargo.toml

# Remove build artifacts from all sub projects so the repository returns to a
# clean state.
clean:
	$(MAKE) -C c_preload_lib clean
	rm -f i2c_tty_redirect
	cargo clean --manifest-path i2c_tap_server/Cargo.toml
	cargo clean --manifest-path i2c_time_writer/Cargo.toml
