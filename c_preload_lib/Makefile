###
# Allow optional cross compilation by setting the CROSS_COMPILE variable.
# When targeting aarch64, use `make CROSS_COMPILE=aarch64-linux-gnu-`.
###
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
CFLAGS ?= -O2 -fPIC -Wall -Wextra
LDFLAGS ?= -shared -ldl
TARGET := libi2c_redirect.so
SRC := i2c_redirect.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
