#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

#include "util.h"

#define VERSION "0.0.7"  // ❗️ Version of this library. Please update this when you make changes. ❗️

uint8_t   bypassed_addrs[128] = {0};
const int I2C_ADDR_MAX        = 127;  // Maximum valid 7-bit I2C address
int       real_i2c_fd;

// Initialize the global log_level variable based on the environment variable LOG_LEVEL
// Valid values are: trace, debug, info, warning, error (case insensitive)
void init_log_level() {
    const char *env_log_level = getenv("LOG_LEVEL");
    if (env_log_level) {
        if (strcasecmp(env_log_level, "trace") == 0) {
            log_level = TRACE;
        } else if (strcasecmp(env_log_level, "debug") == 0) {
            log_level = DEBUG;
        } else if (strcasecmp(env_log_level, "info") == 0) {
            log_level = INFO;
        } else if (strcasecmp(env_log_level, "warning") == 0) {
            log_level = WARN;
        } else if (strcasecmp(env_log_level, "error") == 0) {
            log_level = ERROR;
        }
    }
}

// Initializes the global `bypassed_addrs` array based on the `I2C_INTERCEPT_ADDR_BYPASS` environment variable.
//
// I2C_INTERCEPT_ADDR_BYPASS should be a comma-separated list of I2C addresses,
// in either hexadecimal (e.g. "0x30,0x31") or decimal (e.g. "48,49") format.
//
// For each valid address parsed, bypassed_addrs[addr] is set to true. Address must be
// in the range [0, 127] (that's the valid 7-bit I2C address range). Invalid addresses (not a number,
// out of range, etc.) are logged as warnings.
//
// Example:
//   `I2C_INTERCEPT_ADDR_BYPASS=0x30,49,0x32`
//   => bypassed_addrs[48], bypassed_addrs[49], bypassed_addrs[50] are set to true.
//
// - Only addresses in the range [0, 127] are accepted.
void init_bypass_addr() {
    // Get the environment variable value
    const char *bypass_env = getenv("I2C_INTERCEPT_ADDR_BYPASS");

    // If not set or empty, return early
    if (!bypass_env || !*bypass_env) {
        return;
    }

    // open the real i2c port
    real_i2c_fd = open(I2C_PATH, O_RDWR);
    if (real_i2c_fd < 0) {
        print_error("Failed to open I2C device %s: %s\n", I2C_PATH, strerror(errno));
        return;
    }

    // getenv returns a read-only string, so we need to duplicate it for tokenization
    char *env_copy = strdup(bypass_env);
    if (!env_copy) {
        print_error("Failed to allocate memory for bypass env copy\n");
        return;
    }

    // Tokenize the string by commas
    char *token = strtok(env_copy, ",");
    while (token) {
        char *endptr;
        // Parse each token as a number (hex or decimal)
        long addr = strtol(token, &endptr, 0);  // base 0: auto-detect hex/dec

        // Check for valid conversion and range
        if (*endptr == '\0' && addr >= 0 && addr < 128) {
            bypassed_addrs[addr] = 1;  // Mark address as bypassed

        } else {
            print_warning("Invalid I2C address in I2C_INTERCEPT_ADDR_BYPASS: '%s'\n", token);
        }
        token = strtok(NULL, ",");  // Next token
    }

    char   bypassed_addrs_str[640] = {0};
    size_t len                     = 0;
    for (int i = 0; i < 128; i++) {
        if (bypassed_addrs[i]) {
            int written = snprintf(bypassed_addrs_str + len, sizeof(bypassed_addrs_str) - len, len ? ",0x%02X" : "0x%02X", i);
            if (written > 0 && (len + written < sizeof(bypassed_addrs_str))) {
                len += written;
            }
        }
    }

    print_info("Bypassing I2C addr: %s\n", bypassed_addrs_str);

    free(env_copy);  // Free the duplicated string
}

// This is called when the shared library is loaded. It's basically the entrypoint.
// On library load, it does the following:
// - set the log level based on the `LOG_LEVEL` environment variable
// - open the TTY at `TTY_PATH` and configures it for _blocking_ communication.
// - create a dummy file at `DUMMY_PATH` to be used as a placeholder for the I2C
//   device when we intercept the open.
__attribute__((constructor)) static void intercept_init() {
    init_log_level();
    init_bypass_addr();

    // Create the dummy file if it doesn't exist
    int dummy_fd = open(DUMMY_PATH, O_RDWR | O_CREAT, 0600);
    if (dummy_fd < 0) {
        print_error("Failed to create dummy file %s: %s\n", DUMMY_PATH, strerror(errno));
        _exit(1);
    }
    close(dummy_fd);  // file still exists, but we don't need to keep it open ourselves
    print_info("i2c_intercept.so v%s loaded\n", VERSION);

    open_tty();
}

// This is called when the program using this library is exiting or the library is done.
// On library unload, it does the following:
// - close the TTY file descriptor
// - remove the dummy file at `DUMMY_PATH`
__attribute__((destructor)) static void intercept_cleanup() {
    if (tty_fd >= 0) {
        close(tty_fd);
        tty_fd = -1;
        print_trace("TTY device closed\n");
    }

    if (unlink(DUMMY_PATH) < 0) {  // Remove the dummy file
        print_error("Failed to clean up dummy file %s: %s\n", DUMMY_PATH, strerror(errno));
    }
}

// We intercept the `open64` function to check if the path attempting to be opened
// is the path we want to intercept, `I2C_PATH`. If it is, we fully intercept the
// call, and instead open the dummy file at `DUMMY_PATH` and provide that fd to the
// caller. This is done to avoid needing a real I2C device or kernel module at the
// actual `I2C_PATH`. This is important because Docker containers do not have
// access to the host kernel's I2C subsystem, making this library fully portable.
//
// The reason we use `open64` instead of `open` is that for the I2C crate that
// we've been using in the GNC project, linux-embedded-hal, uses `open64`.
int open64(const char *pathname, int flags, ...) {
    static int (*real_open64)(const char *, int, ...) = NULL;
    mode_t mode                                       = 0;

    if (!real_open64) {
        real_open64 = dlsym(RTLD_NEXT, "open64");
        if (!real_open64) {
            print_error("Error resolving original open64: %s\n", dlerror());
            errno = ENOSYS;
            _exit(1);
        }
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (strcmp(pathname, I2C_PATH) == 0) {
        print_debug("Intercepted open64 of %s\n", I2C_PATH);
        int dummy_fd = open(DUMMY_PATH, O_RDWR);
        if (dummy_fd < 0) {
            print_error("Failed to open dummy file %s: %s\n", DUMMY_PATH, strerror(errno));
            return -1;
        }
        return dummy_fd;  // Return the dummy file descriptor instead of the real I2C device
    }
    return real_open64(pathname, flags, mode);
}

int close(int fd) {
    static int (*real_close)(int) = NULL;

    // resolve the original close function
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        if (!real_close) {
            print_error("Error resolving original close: %s\n", dlerror());
            errno = ENOSYS;  // Function not implemented
            _exit(1);
        }
    }
    if (is_redir_i2c(fd)) {
        print_trace("Intercepted close of i2c_addr=0x%02X (%d)\n", fd, fd_i2c_addr[fd], fd_i2c_addr[fd]);
    }
    return real_close(fd);
}

// `ioctl` has several request options, but the ones we are interested in are
// `I2C_SLAVE` and `I2C_SLAVE_FORCE`. These commands are used to set the I2C
// address for the device that is being accessed, and they are set per file
// descriptor. Because we're intercepting calls, we have to manually track the I2C
// address for each file descriptor that we intercept, which we do using the
// `fd_i2c_addr` array.
int ioctl(int fd, unsigned long request, ...) {
    static int (*real_ioctl)(int, unsigned long, void *) = NULL;
    const int I2C_SLAVE                                  = 0x0703;  // I2C_SLAVE request code
    const int I2C_SLAVE_FORCE                            = 0x0706;  // I2C_SLAVE_FORCE request code

    // resolve the original ioctl function
    if (!real_ioctl) {
        real_ioctl = dlsym(RTLD_NEXT, "ioctl");
        if (!real_ioctl) {
            print_error("Error resolving original ioctl: %s\n", dlerror());
            _exit(1);
        }
    }

    // handle the variadic args
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);

    // check if the file descriptor corresponds to our I2C device
    if (is_redir_i2c(fd)) {

        if (request == I2C_SLAVE || request == I2C_SLAVE_FORCE) {  // request == set I2C_SLAVE or set I2C_SLAVE_FORCE
            fd_i2c_addr[fd] = (uint8_t)(uintptr_t)arg;
            if (bypassed_addrs[fd_i2c_addr[fd]]) {
                print_debug("Bypassing intercepted ioctl: request=0x%lx (set I2C address: 0x%02X)\n", request, fd_i2c_addr[fd]);
                return real_ioctl(real_i2c_fd, request, arg);
            }

            print_debug("Intercepted ioctl: request=0x%lx (set I2C address: 0x%02X)\n", request, fd_i2c_addr[fd]);
        } else if (arg) {
            print_trace("Intercepted ioctl: request=0x%lx, arg=%p\n", request, arg);
        } else {
            print_trace("Intercepted ioctl: request=0x%lx, arg=NULL\n", request);
        }
        return 0;
    }
    return real_ioctl(fd, request, arg);
}

// This one is straightforward. When an I2C write call is made, we check if the file
// descriptor is one of the I2C fds we are intercepting. If it is, we extract the
// I2C address from the `fd_i2c_addr` array, which was set by the previous `ioctl`
// call, and then we format the data to be sent to the TTY in the message format
// described above.
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;

    // resolve the original write function
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
        if (!real_write) {
            print_error("Error resolving original write: %s", dlerror());
            _exit(1);
        }
    }

    // Check if the file descriptor corresponds to our I2C device
    if (is_redir_i2c(fd)) {
        // if bypassed address, then do the real write
        if (bypassed_addrs[fd_i2c_addr[fd]]) {
            print_debug("Bypassing intercepted write to i2c_addr=0x%02X (%d)\n", fd_i2c_addr[fd], fd_i2c_addr[fd]);
            return real_write(real_i2c_fd, buf, count);
        }

        print_debug("Intercepted write to i2c_addr=0x%02X (%d), %zu bytes: ", fd, fd_i2c_addr[fd], fd_i2c_addr[fd], count);
        if (log_level <= DEBUG) {
            print_buffer((const unsigned char *)buf, count);
            printf("\n");
        }

        // check if the TTY device is available
        if (tty_fd >= 0) {
            unsigned char *tty_buf = malloc(count + 2);
            if (!tty_buf) {
                print_error("Failed to allocate memory for TTY buffer\n");
                errno = ENOMEM;  // Not enough space
                return -1;
            }

            // construct and send the message to send to the TTY
            tty_buf[0] = fd_i2c_addr[fd];     // I2C address
            tty_buf[1] = 0;                   // Command byte, 0 for write
            memcpy(tty_buf + 2, buf, count);  // original data
            pthread_mutex_lock(&tty_mutex);
            ssize_t sent_bytes = real_write(tty_fd, tty_buf, count + 2);
            free(tty_buf);
            pthread_mutex_unlock(&tty_mutex);

            if (sent_bytes < 0) {
                print_error("Failed to write to TTY device\n");
                errno = EIO;  // Input/output error
                return -1;
            }

            print_trace("Sent %zd bytes to TTY device\n", sent_bytes);
            return count;
        } else {
            print_error("TTY device not available, cannot write to it\n");
            errno = ENODEV;  // No such device
            return -1;
        }
    }
    return real_write(fd, buf, count);
}

// Unlike writing, we can't immediately read. We must first send a read request to
// the TTY. To do so, we send a request to the TTY in the message format, but set
// the command type to 1 (read), and send 8 bytes of null data. Then, the TTY is
// expected to respond with the data read from the I2C device.
//
// The 8 bytes of null data are used to pad the message to 10 bytes, which is
// simply for easier framing on the receive side, as the current I2C Slice protocol
// issues commands in 10-byte frames. Otherwise, it is not strictly necessary.
//
// Because TTY is full duplex, and there may be multiple I2C fds open at the same
// time, the may be multiple writes and read (which is itself composed of a
// write-then-read) happening concurrently. We must ensure that the read request
// and response are handled atomically; to do this, we lock the section around TTY
// access, essentially making our I/O operations half-duplex like real I2C.
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t)        = NULL;
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        if (!real_read) {
            print_error("Error resolving original read: %s\n", dlerror());
            _exit(1);
        }
    }
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
        if (!real_write) {
            print_error("Error resolving original write: %s\n", dlerror());
            _exit(1);
        }
    }
    if (is_redir_i2c(fd)) {
        // if bypassed address, then do the real read
        if (bypassed_addrs[fd_i2c_addr[fd]]) {
            print_debug("Bypassing intercepted read to i2c_addr=0x%02X (%d)\n", fd_i2c_addr[fd], fd_i2c_addr[fd]);
            return real_read(real_i2c_fd, buf, count);
        }

        print_debug("Intercepted read from i2c_addr=0x%02X (%d), %zu bytes\n", fd_i2c_addr[fd], fd_i2c_addr[fd], count);
        if (tty_fd >= 0) {
            // Send a read request message to the TTY device
            const uint8_t REQ_LEN = 10;                        // The length of the request message.
                                                               // This doesn't have to be 10 bytes. It's just a convenient size for framing on the TTY side
            unsigned char tty_buf[REQ_LEN];                    // Buffer to hold the request message
            tty_buf[0] = fd_i2c_addr[fd];                      // I2C address
            tty_buf[1] = 1;                                    // Command byte, 1 for read
            for (int i = 2; i < REQ_LEN; i++) tty_buf[i] = 0;  // Fill the rest with zeros to make it 10 bytes
            print_trace("Sending read request for I2C address 0x%02X (%d) with data: ", fd_i2c_addr[fd], fd_i2c_addr[fd]);
            if (log_level <= TRACE) {
                print_buffer(tty_buf, REQ_LEN);
                printf("\n");
            }
            pthread_mutex_lock(&tty_mutex);
            ssize_t sent_bytes = real_write(tty_fd, tty_buf, 10);
            print_trace("Sent %zd bytes to TTY device for read request\n", sent_bytes);
            if (sent_bytes < 0) {
                pthread_mutex_unlock(&tty_mutex);
                print_error("Failed to write to TTY device\n");
                errno = EIO;  // Input/output error
                return -1;
            }

            // Now read the full response message from the TTY device. Per the configuration when we
            // opened the TTY, we expect 62 bytes back (defined by the I2C Slice protocol), and will
            // time out after 100 ms (that's the lowest possible timeout). Previously, we attempted
            // to read only the caller-requested number of bytes. If the TTY sent more than that,
            // leftover bytes would remain in the TTY buffer, causing subsequent reads to become
            // misaligned and eventually fail. To avoid this, read all expected bytes and then return
            // only the portion requested by the caller.

            const size_t RESP_LEN = 62;  // expected response length from TTY
            unsigned char resp_buf[RESP_LEN];
            size_t total_read = 0;
            while (total_read < RESP_LEN) {
                ssize_t n = real_read(tty_fd, resp_buf + total_read, RESP_LEN - total_read);
                if (n <= 0) {
                    pthread_mutex_unlock(&tty_mutex);
                    print_error("Failed to read from TTY device\n");
                    errno = EIO;  // Input/output error
                    return -1;
                }
                total_read += (size_t)n;
            }
            pthread_mutex_unlock(&tty_mutex);

            size_t copy_len = count < RESP_LEN ? count : RESP_LEN;
            memcpy(buf, resp_buf, copy_len);

            print_debug("Read %zu bytes from TTY device (requested %zu)\n", total_read, count);
            if (log_level <= DEBUG) {
                print_buffer((const unsigned char *)resp_buf, total_read);
                printf("\n");
            }
            return copy_len;

        } else {
            print_error("TTY device not available, cannot read from it\n");
            errno = ENODEV;  // No such device
            return -1;
        }
    }
    return real_read(fd, buf, count);
}
