# Simple Makefile to build the static I²C socket proxy preload library.

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fPIC
LDFLAGS ?= -shared -ldl

LIB := libi2c_static_proxy.so
SRC := i2c_static_proxy.c

all: $(LIB)

$(LIB): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

clean:
	rm -f $(LIB)

.PHONY: all clean
