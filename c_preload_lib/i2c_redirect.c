/*
 * i2c_redirect.c
 * ---------------
 * LD_PRELOAD library that intercepts common I²C related syscalls and emits
 * JSON descriptions of the traffic to a Unix domain socket. When the
 * I2C_PROXY_PASSTHROUGH environment variable is unset, operations are
 * swallowed after being logged so nothing touches the real hardware.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef FD_LIMIT
#define FD_LIMIT 4096
#endif

// --- real syscalls
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static ssize_t (*real_write)(int, const void *, size_t) = NULL;
static int (*real_ioctl)(int, unsigned long, ...) = NULL;
static int (*real_close)(int) = NULL;

/* Guard to avoid recursively intercepting our own syscalls. */
static _Thread_local int in_hook = 0;

/* Socket management state: either connect to a path or use an existing FD. */
static int sock_fd = -1;
static int sock_fd_from_env = -1;
static char *sock_path = NULL;
static int passthrough = 0; /* Whether to forward I²C operations. */

/* Track which file descriptors correspond to I²C devices and current address. */
static _Atomic int is_i2c_fd[FD_LIMIT];
static _Atomic int current_addr[FD_LIMIT]; // -1 if unknown

/* Resolve the real libc symbol addresses the first time we need them. */
static void ensure_resolved(void) {
    if (real_open && real_open64 && real_openat && real_write && real_ioctl && real_close) return;
    real_open   = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_write  = dlsym(RTLD_NEXT, "write");
    real_ioctl  = dlsym(RTLD_NEXT, "ioctl");
    real_close  = dlsym(RTLD_NEXT, "close");
}

/* Return current time in nanoseconds. */
static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Encode a byte buffer as lower-case hex. */
static void hex_encode(char *dst, const unsigned char *src, size_t n) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2*i]   = hex[(src[i] >> 4) & 0xF];
        dst[2*i+1] = hex[src[i] & 0xF];
    }
    dst[2*n] = '\0';
}

/* Test if a path looks like an I²C device node. */
static int is_i2c_path(const char *path) {
    return (path && strncmp(path, "/dev/i2c-", 9) == 0);
}

/* Record whether a file descriptor refers to an I²C device. */
static void mark_i2c_fd(int fd, int yes) {
    if (fd >= 0 && fd < FD_LIMIT) {
        atomic_store(&is_i2c_fd[fd], yes ? 1 : 0);
        if (yes) atomic_store(&current_addr[fd], -1);
    }
}

/* Query the mark applied by mark_i2c_fd. */
static int is_marked_i2c(int fd) {
    if (fd >= 0 && fd < FD_LIMIT) return atomic_load(&is_i2c_fd[fd]) != 0;
    return 0;
}

// --- socket connect & send (with retry)
/* Connect to the proxy Unix socket, returning the new fd or -1 on error. */
static int connect_socket_path(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n >= sizeof(sa.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    memcpy(sa.sun_path, path, n+1);

    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        int e = errno; close(fd); errno = e; return -1;
    }
    return fd;
}

/* Establish the global socket descriptor if not already connected. */
static void ensure_socket(void) {
    if (sock_fd >= 0) return;

    in_hook++;
    if (sock_fd_from_env >= 0) {
        sock_fd = sock_fd_from_env;
    } else if (sock_path) {
        int fd = connect_socket_path(sock_path);
        if (fd >= 0) sock_fd = fd;
    }
    in_hook--;
}

/*
 * Send len bytes, reconnecting once on EPIPE/ECONNRESET. If reconnection fails
 * the data is silently dropped.
 */
static void send_all_or_drop(const char *buf, size_t len) {
    if (in_hook) return;
    if (sock_fd < 0) ensure_socket();
    if (sock_fd < 0) return;

    ssize_t off = 0;
    while ((size_t)off < len) {
        ssize_t n = send(sock_fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += n;
            continue;
        }
        if (n < 0 && (errno == EPIPE || errno == ECONNRESET)) {
            /* reconnect once */
            if (sock_fd_from_env < 0 && sock_path) {
                close(sock_fd);
                sock_fd = -1;
                ensure_socket();
                if (sock_fd < 0) return; /* give up */
                continue; /* retry loop */
            } else {
                return; /* cannot reconnect fd-from-env */
            }
        } else {
            return; /* other error -> drop */
        }
    }
}

/* Emit a line of JSON, appending a newline if needed. */
static void emit_json_line(const char *s) {
    size_t len = strlen(s);
    if (len && s[len-1] == '\n') {
        send_all_or_drop(s, len);
    } else {
        send_all_or_drop(s, len);
        send_all_or_drop("\n", 1);
    }
}

/* printf-style helper that formats a JSON line and sends it. */
static void emitf(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void emitf(const char *fmt, ...) {
    char buf[65536];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    emit_json_line(buf);
}

// --- init
/* Constructor that initializes environment-derived settings. */
__attribute__((constructor))
static void init_i2c_redirect(void) {
    ensure_resolved();

    const char *p = getenv("I2C_PROXY_PASSTHROUGH");
    passthrough = (p && *p && strcmp(p, "0") != 0) ? 1 : 0;

    const char *fd_str = getenv("I2C_PROXY_SOCK_FD");
    if (fd_str && *fd_str) {
        char *end = NULL;
        long v = strtol(fd_str, &end, 10);
        if (end && *end == '\0' && v >= 0 && v < 1<<30) sock_fd_from_env = (int)v;
    }
    const char *sp = getenv("I2C_PROXY_SOCK");
    if (sp && *sp) sock_path = strdup(sp);
}

// --- open family
/* Common helper for open/open64/openat hooks. */
static int handle_open_common(const char *path, int flags, mode_t *mode_opt, int which) {
    ensure_resolved();
    int fd = -1;
    in_hook++;
    if (which == 0) {
        if (flags & O_CREAT) fd = real_open(path, flags, mode_opt ? *mode_opt : 0);
        else fd = real_open(path, flags);
    } else if (which == 1) {
        if (flags & O_CREAT) fd = real_open64(path, flags, mode_opt ? *mode_opt : 0);
        else fd = real_open64(path, flags);
    }
    in_hook--;
    if (fd >= 0 && is_i2c_path(path)) {
        mark_i2c_fd(fd, 1);
        emitf("{\"type\":\"open\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"path\":\"%s\"}",
              getpid(), now_ns(), fd, path);
    }
    return fd;
}

int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        return handle_open_common(path, flags, &mode, 0);
    }
    return handle_open_common(path, flags, NULL, 0);
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        return handle_open_common(path, flags, &mode, 1);
    }
    return handle_open_common(path, flags, NULL, 1);
}

int openat(int dirfd, const char *path, int flags, ...) {
    ensure_resolved();
    mode_t mode = 0;
    int fd;
    in_hook++;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        fd = real_openat(dirfd, path, flags, mode);
    } else {
        fd = real_openat(dirfd, path, flags);
    }
    in_hook--;
    if (fd >= 0 && is_i2c_path(path)) {
        mark_i2c_fd(fd, 1);
        emitf("{\"type\":\"open\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"path\":\"%s\"}",
              getpid(), now_ns(), fd, path);
    }
    return fd;
}

// --- close
int close(int fd) {
    ensure_resolved();
    if (is_marked_i2c(fd)) {
        emitf("{\"type\":\"close\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d}",
              getpid(), now_ns(), fd);
        mark_i2c_fd(fd, 0);
    }
    in_hook++;
    int r = real_close(fd);
    in_hook--;
    return r;
}

// --- write
/* Hook for the write syscall that logs data written to I²C descriptors. */
ssize_t write(int fd, const void *buf, size_t count) {
    ensure_resolved();
    if (in_hook) return real_write(fd, buf, count);

    if (is_marked_i2c(fd)) {
        int addr = -1;
        if (fd >= 0 && fd < FD_LIMIT) addr = atomic_load(&current_addr[fd]);

        const size_t max_dump = 8192;
        size_t n = count > max_dump ? max_dump : count;
        char *hex = malloc(n * 2 + 1);
        if (hex) {
            hex_encode(hex, (const unsigned char *)buf, n);
            emitf("{\"type\":\"write\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"addr\":%d,\"len\":%zu,\"data_hex\":\"%s\"}%s",
                  getpid(), now_ns(), fd, addr, count, hex, (count>max_dump? " /*truncated*/": ""));
            free(hex);
        }
        if (!passthrough) return (ssize_t)count;
    }

    in_hook++;
    ssize_t r = real_write(fd, buf, count);
    in_hook--;
    return r;
}

// --- ioctl
/* Emit detailed information for the I2C_RDWR ioctl. */
static void log_i2c_rdwr(int fd, struct i2c_rdwr_ioctl_data *d) {
    long long ts = now_ns();
    emitf("{\"type\":\"ioctl_rdwr\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"nmsgs\":%d,\"detail\":[",
          getpid(), ts, fd, (int)d->nmsgs);
    for (int i = 0; i < (int)d->nmsgs; i++) {
        struct i2c_msg *m = &d->msgs[i];
        emitf("{\"idx\":%d,\"addr\":%u,\"flags\":%u,\"len\":%u,", i, m->addr, m->flags, m->len);
        if (m->flags & I2C_M_RD) {
            emitf("\"dir\":\"read\"}%s", (i+1<(int)d->nmsgs?",":""));
        } else {
            size_t take = m->len > 8192 ? 8192 : m->len;
            char *hex = malloc(take*2 + 1);
            if (hex) {
                hex_encode(hex, (const unsigned char*)m->buf, take);
                emitf("\"dir\":\"write\",\"data_hex\":\"%s\"}%s", hex, (i+1<(int)d->nmsgs?",":""));
                free(hex);
            } else {
                emitf("\"dir\":\"write\",\"data_hex\":\"\"}%s", (i+1<(int)d->nmsgs?",":""));
            }
        }
    }
    emitf("]}");
}

/* Main ioctl hook that handles several I²C-specific requests. */
int ioctl(int fd, unsigned long req, ...) {
    ensure_resolved();
    va_list ap;
    va_start(ap, req);

    if (!is_marked_i2c(fd)) {
        void *arg = va_arg(ap, void *);
        va_end(ap);
        in_hook++;
        int r = real_ioctl(fd, req, arg);
        in_hook--;
        return r;
    }

    int ret = 0;
    if (req == I2C_SLAVE || req == I2C_SLAVE_FORCE) {
        unsigned long addr = va_arg(ap, unsigned long);
        va_end(ap);
        if (fd >= 0 && fd < FD_LIMIT) atomic_store(&current_addr[fd], (int)addr);
        emitf("{\"type\":\"ioctl_set_slave\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"addr\":%lu,\"force\":%s}",
              getpid(), now_ns(), fd, addr, (req==I2C_SLAVE_FORCE? "true":"false"));
        if (passthrough) {
            in_hook++; ret = real_ioctl(fd, req, addr); in_hook--;
        } else ret = 0;
        return ret;
    }

    if (req == I2C_RDWR) {
        struct i2c_rdwr_ioctl_data *d = va_arg(ap, struct i2c_rdwr_ioctl_data *);
        va_end(ap);
        if (d) log_i2c_rdwr(fd, d);
        if (passthrough) { in_hook++; ret = real_ioctl(fd, req, d); in_hook--; } else ret = 0;
        return ret;
    }

    if (req == I2C_SMBUS) {
        struct i2c_smbus_ioctl_data *sd = va_arg(ap, struct i2c_smbus_ioctl_data *);
        va_end(ap);
        if (sd) {
            emitf("{\"type\":\"ioctl_smbus\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,"
                  "\"read\":%s,\"command\":%u,\"size\":%u}",
                  getpid(), now_ns(), fd,
                  (sd->read_write==I2C_SMBUS_READ? "true":"false"),
                  sd->command, sd->size);
        }
        if (passthrough) { in_hook++; ret = real_ioctl(fd, req, sd); in_hook--; } else ret = 0;
        return ret;
    }

    void *arg = va_arg(ap, void *);
    va_end(ap);
    emitf("{\"type\":\"ioctl_other\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"req\":%lu}",
          getpid(), now_ns(), fd, req);
    if (passthrough) { in_hook++; ret = real_ioctl(fd, req, arg); in_hook--; } else ret = 0;
    return ret;
}
