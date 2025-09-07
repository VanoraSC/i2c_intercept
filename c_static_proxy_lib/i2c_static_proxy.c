/*
 * i2c_static_proxy.c
 * -------------------
 * New LD_PRELOAD shared library that intercepts I²C bus activity and forwards
 * the traffic through a Unix domain socket.  A `socat` helper is spawned on
 * load to bridge the socket to a synthetic UART device so external tools can
 * monitor or emulate the bus.  All communication is proxied transparently and
 * no payload mutation occurs.
 *
 * The implementation is intentionally self contained; configuration is provided
 * via compile time constants rather than environment variables.  Adjust the
 * macro definitions below or pass alternatives on the compiler command line to
 * tailor the behavior.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FD_LIMIT
#define FD_LIMIT 4096
#endif

/* ------------------------------------------------------------------------- */
/* Configuration constants that can be overridden at compile time.           */
/* ------------------------------------------------------------------------- */

/* Path to the Unix domain socket used to proxy I²C traffic. */
#ifndef I2C_PROXY_SOCKET_PATH
#define I2C_PROXY_SOCKET_PATH "/tmp/ttyS22.tap.sock"
#endif

/* Path to the synthetic UART device that the socket will be bridged to. */
#ifndef SOCAT_TTY_PATH
#define SOCAT_TTY_PATH "/dev/ttyS22"
#endif

/* Absolute path to the socat binary used to create the bridge. */
#ifndef SOCAT_BINARY
#define SOCAT_BINARY "/media/data/socat"
#endif

/* ------------------------------------------------------------------------- */
/* State used by the interceptor.                                           */
/* ------------------------------------------------------------------------- */

/* Real libc syscall pointers resolved with dlsym() on first use. */
static int      (*real_open)(const char *, int, ...)            = NULL;
static int      (*real_open64)(const char *, int, ...)          = NULL;
static int      (*real_openat)(int, const char *, int, ...)     = NULL;
static ssize_t  (*real_read)(int, void *, size_t)               = NULL;
static ssize_t  (*real_write)(int, const void *, size_t)        = NULL;
static int      (*real_ioctl)(int, unsigned long, ...)          = NULL;
static int      (*real_close)(int)                              = NULL;

/* Thread local flag preventing recursive hooks when this library performs
 * its own system calls. */
static _Thread_local int in_hook = 0;

/* Socket state.  All intercepted traffic is sent to this Unix domain socket. */
static int sock_fd = -1;

/* Track which file descriptors correspond to I²C devices and their active
 * slave addresses.  All access is serialized by `i2c_mutex` so explicit atomic
 * operations are unnecessary. */
static int is_i2c_fd[FD_LIMIT];
static int current_addr[FD_LIMIT]; /* -1 when unknown */

/* Global mutex guarding every access to the above state and all I²C
 * transactions.  Only one thread may interact with the bus at a time. */
static pthread_mutex_t i2c_mutex = PTHREAD_MUTEX_INITIALIZER;

/* PID of the helper socat process that bridges the proxy socket to a PTY. */
static pid_t socat_pid = -1;

/* ------------------------------------------------------------------------- */
/* Utility helpers.                                                         */
/* ------------------------------------------------------------------------- */

/* Resolve the real libc symbols the first time we need them. */
static void ensure_resolved(void) {
    if (real_open) return;
    real_open   = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_read   = dlsym(RTLD_NEXT, "read");
    real_write  = dlsym(RTLD_NEXT, "write");
    real_ioctl  = dlsym(RTLD_NEXT, "ioctl");
    real_close  = dlsym(RTLD_NEXT, "close");
}

/* Simple test for device nodes that look like /dev/i2c-X. */
static int is_i2c_path(const char *path) {
    return path && strncmp(path, "/dev/i2c-", 9) == 0;
}

/* Mark a descriptor as I²C-aware so later calls can be redirected.  This
 * function acquires the global mutex to serialize updates with any concurrent
 * transactions. */
static void mark_i2c(int fd, int enable) {
    if (fd < 0 || fd >= FD_LIMIT) return;
    pthread_mutex_lock(&i2c_mutex);
    is_i2c_fd[fd] = enable;
    if (!enable) current_addr[fd] = -1;
    pthread_mutex_unlock(&i2c_mutex);
}

/* Quick helper used when the caller already holds `i2c_mutex`. */
static int fd_is_i2c_unlocked(int fd) {
    return fd >= 0 && fd < FD_LIMIT && is_i2c_fd[fd];
}

/* Connect to the proxy socket if not already connected. */
static void ensure_socket(void) {
    if (sock_fd >= 0) return;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, I2C_PROXY_SOCKET_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); return; }
    sock_fd = fd;
}

/* Send exactly len bytes, retrying on short writes.  Returns 0 on success. */
static int send_all(const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t r = send(sock_fd, p, len, 0);
        if (r <= 0) return -1;
        p += r; len -= (size_t)r;
    }
    return 0;
}

/* Receive exactly len bytes.  Returns 0 on success. */
static int recv_all(void *buf, size_t len) {
    char *p = buf;
    while (len > 0) {
        ssize_t r = recv(sock_fd, p, len, 0);
        if (r <= 0) return -1;
        p += r; len -= (size_t)r;
    }
    return 0;
}

/* Spawn the socat helper that bridges the proxy socket to the synthetic TTY. */
static void spawn_socat(void) {
    if (socat_pid > 0) return; /* already running */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process: execute socat.  It listens on the fixed socket path
         * and creates a PTY at SOCAT_TTY_PATH. */
        char listen_spec[128];
        char pty_spec[128];
        snprintf(listen_spec, sizeof(listen_spec),
                 "UNIX-LISTEN:%s,fork,mode=777", I2C_PROXY_SOCKET_PATH);
        snprintf(pty_spec, sizeof(pty_spec),
                 "PTY,link=%s,raw,echo=0,b115200", SOCAT_TTY_PATH);
        execl(SOCAT_BINARY, "socat", listen_spec, pty_spec, (char *)NULL);
        _exit(1); /* execl only returns on failure */
    }
    if (pid > 0) {
        socat_pid = pid;
    }
}

/* Ensure the socat helper is alive, restarting it if necessary. */
static void ensure_socat(void) {
    if (socat_pid > 0) {
        if (waitpid(socat_pid, NULL, WNOHANG) == 0) return; /* still alive */
    }
    socat_pid = -1;
    spawn_socat();
}

/* ------------------------------------------------------------------------- */
/* Hooks for common syscalls.                                               */
/* ------------------------------------------------------------------------- */

/* Common open handler used by open() and open64(). */
static int handle_open(const char *path, int flags, mode_t *mode, int use64) {
    ensure_resolved();
    int fd;
    in_hook++;
    if (use64) {
        if (flags & O_CREAT) fd = real_open64(path, flags, mode ? *mode : 0);
        else fd = real_open64(path, flags);
    } else {
        if (flags & O_CREAT) fd = real_open(path, flags, mode ? *mode : 0);
        else fd = real_open(path, flags);
    }
    in_hook--;
    if (fd >= 0 && is_i2c_path(path)) {
        mark_i2c(fd, 1);
    }
    return fd;
}

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        return handle_open(path, flags, &mode, 0);
    }
    return handle_open(path, flags, NULL, 0);
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        return handle_open(path, flags, &mode, 1);
    }
    return handle_open(path, flags, NULL, 1);
}

int openat(int dirfd, const char *path, int flags, ...) {
    ensure_resolved();
    int fd;
    mode_t mode = 0;
    in_hook++;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        fd = real_openat(dirfd, path, flags, mode);
    } else {
        fd = real_openat(dirfd, path, flags);
    }
    in_hook--;
    if (fd >= 0 && is_i2c_path(path)) {
        mark_i2c(fd, 1);
    }
    return fd;
}

int close(int fd) {
    ensure_resolved();
    mark_i2c(fd, 0);
    return real_close(fd);
}

/* Hooked read() that proxies data from the selected I²C slave over the socket. */
ssize_t read(int fd, void *buf, size_t count) {
    ensure_resolved();
    if (in_hook) return real_read(fd, buf, count);
    pthread_mutex_lock(&i2c_mutex); /* exclusive bus access */
    if (!fd_is_i2c_unlocked(fd)) {
        pthread_mutex_unlock(&i2c_mutex);
        in_hook++; ssize_t r = real_read(fd, buf, count); in_hook--; return r;
    }
    ensure_socat();           /* make sure bridge is running */
    ensure_socket();          /* connect to monitoring socket */
    if (sock_fd < 0) { pthread_mutex_unlock(&i2c_mutex); return -1; }
    int addr = current_addr[fd];
    size_t len = count > 255 ? 255 : count;
    unsigned char hdr[3] = { (unsigned char)addr, 1, (unsigned char)len };
    ssize_t r;
    if (send_all(hdr, sizeof(hdr)) == 0 && recv_all(buf, len) == 0) {
        r = (ssize_t)len;
    } else {
        r = -1;
    }
    pthread_mutex_unlock(&i2c_mutex);
    return r;
}

/* Hooked write() that forwards outbound data for the current I²C slave. */
ssize_t write(int fd, const void *buf, size_t count) {
    ensure_resolved();
    if (in_hook) return real_write(fd, buf, count);
    pthread_mutex_lock(&i2c_mutex); /* exclusive bus access */
    if (!fd_is_i2c_unlocked(fd)) {
        pthread_mutex_unlock(&i2c_mutex);
        in_hook++; ssize_t r = real_write(fd, buf, count); in_hook--; return r;
    }
    ensure_socat();           /* make sure bridge is running */
    ensure_socket();          /* connect to monitoring socket */
    if (sock_fd < 0) { pthread_mutex_unlock(&i2c_mutex); return -1; }
    int addr = current_addr[fd];
    size_t len = count > 255 ? 255 : count;
    unsigned char hdr[3] = { (unsigned char)addr, 0, (unsigned char)len };
    ssize_t r;
    if (send_all(hdr, sizeof(hdr)) == 0 && send_all(buf, len) == 0) {
        r = (ssize_t)len;
    } else {
        r = -1;
    }
    pthread_mutex_unlock(&i2c_mutex);
    return r;
}

/* Intercept ioctl() to handle I²C address selection and transactions. */
int ioctl(int fd, unsigned long req, ...) {
    ensure_resolved();
    va_list ap; va_start(ap, req);
    pthread_mutex_lock(&i2c_mutex); /* serialize ioctls with data transfers */
    if (!fd_is_i2c_unlocked(fd)) {
        pthread_mutex_unlock(&i2c_mutex);
        void *arg = va_arg(ap, void *); va_end(ap);
        in_hook++; int ret = real_ioctl(fd, req, arg); in_hook--; return ret;
    }

    int ret = 0;
    if (req == I2C_SLAVE || req == I2C_SLAVE_FORCE) {
        unsigned long addr = va_arg(ap, unsigned long); va_end(ap);
        if (fd >= 0 && fd < FD_LIMIT) current_addr[fd] = (int)addr;
        pthread_mutex_unlock(&i2c_mutex);
        return 0; /* pretend success */
    }

    if (req == I2C_RDWR) {
        struct i2c_rdwr_ioctl_data *d = va_arg(ap, struct i2c_rdwr_ioctl_data *);
        va_end(ap);
        if (!d) { pthread_mutex_unlock(&i2c_mutex); return -1; }
        ensure_socat();
        ensure_socket();
        if (sock_fd < 0) { pthread_mutex_unlock(&i2c_mutex); return -1; }
        for (int i = 0; i < d->nmsgs; i++) {
            struct i2c_msg *m = &d->msgs[i];
            size_t len = m->len > 255 ? 255 : m->len;
            unsigned char hdr[3] = { (unsigned char)m->addr,
                                     (m->flags & I2C_M_RD) ? 1 : 0,
                                     (unsigned char)len };
            if (send_all(hdr, sizeof(hdr)) != 0) { ret = -1; break; }
            if (m->flags & I2C_M_RD) {
                if (recv_all(m->buf, len) != 0) { ret = -1; break; }
            } else {
                if (send_all(m->buf, len) != 0) { ret = -1; break; }
            }
        }
        pthread_mutex_unlock(&i2c_mutex);
        return ret;
    }

    if (req == I2C_SMBUS) {
        struct i2c_smbus_ioctl_data *sd = va_arg(ap, struct i2c_smbus_ioctl_data *);
        va_end(ap);
        if (!sd) { pthread_mutex_unlock(&i2c_mutex); return -1; }
        ensure_socat();
        ensure_socket();
        if (sock_fd < 0) { pthread_mutex_unlock(&i2c_mutex); return -1; }
        int addr = current_addr[fd];
        unsigned char hdr[3];
        unsigned char data[34];
        size_t len = 0;
        hdr[0] = (unsigned char)addr;
        hdr[1] = (sd->read_write == I2C_SMBUS_READ) ? 1 : 0;
        switch (sd->size) {
            case I2C_SMBUS_BYTE:
                len = 1; data[0] = sd->data->byte; break;
            case I2C_SMBUS_BYTE_DATA:
                len = 2; data[0] = sd->command; data[1] = sd->data->byte; break;
            case I2C_SMBUS_WORD_DATA:
                len = 3; data[0] = sd->command; data[1] = sd->data->word & 0xFF;
                        data[2] = (sd->data->word >> 8) & 0xFF; break;
            default:
                len = 0; break; /* unsupported sizes */
        }
        hdr[2] = (unsigned char)len;
        ret = send_all(hdr, sizeof(hdr));
        if (ret == 0) {
            if (hdr[1] == 0) {
                if (len && send_all(data, len) != 0) ret = -1;
            } else {
                if (len && recv_all(data, len) != 0) ret = -1;
                if (ret == 0) {
                    if (sd->size == I2C_SMBUS_BYTE) {
                        sd->data->byte = data[0];
                    } else if (sd->size == I2C_SMBUS_BYTE_DATA) {
                        sd->data->byte = data[1];
                    } else if (sd->size == I2C_SMBUS_WORD_DATA) {
                        sd->data->word = data[1] | ((uint16_t)data[2] << 8);
                    }
                }
            }
        }
        pthread_mutex_unlock(&i2c_mutex);
        return ret;
    }

    /* Unknown request on an I²C descriptor: acknowledge without action so the
     * caller continues to run. */
    (void)va_arg(ap, void *); va_end(ap);
    pthread_mutex_unlock(&i2c_mutex);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Library constructor/destructor.                                         */
/* ------------------------------------------------------------------------- */

__attribute__((constructor))
static void init_proxy(void) {
    for (int i = 0; i < FD_LIMIT; i++) {
        is_i2c_fd[i] = 0;
        current_addr[i] = -1;
    }
    spawn_socat();
}

__attribute__((destructor))
static void shutdown_proxy(void) {
    if (sock_fd >= 0) close(sock_fd);
    if (socat_pid > 0) {
        kill(socat_pid, SIGTERM);
        waitpid(socat_pid, NULL, 0);
    }
}

