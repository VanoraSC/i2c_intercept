###
# Allow optional cross compilation by setting the CROSS_COMPILE variable.
# When targeting aarch64, use `make CROSS_COMPILE=aarch64-linux-gnu-`.
###
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
# Default to building an optimized shared library without debug asserts.
# Users can supply their own CFLAGS to adjust optimization levels.
# Threaded operations require pthread support for mutex locking around the
# proxy socket.
CFLAGS ?= -O2 -DNDEBUG -fPIC -Wall -Wextra -pthread
LDFLAGS ?= -shared -ldl -pthread
TARGET := libi2c_redirect.so
SRC := i2c_redirect.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
