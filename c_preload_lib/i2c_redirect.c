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
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#ifndef FD_LIMIT
#define FD_LIMIT 4096
#endif

/*
 * Absolute path to the socat binary used when bridging I²C traffic to a
 * serial device.  Using a fixed path avoids relying on the invoking process'
 * PATH environment and ensures the intended helper is executed.
 */
#define SOCAT_BINARY "/media/data/socat"

// --- real syscalls
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
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
/* When set, emit binary frames instead of JSON. */
static int raw_mode = 0;

/*
 * PID of an optional socat helper process.  When I2C_SOCAT_TTY is configured
 * we spawn a child that bridges a Unix domain socket to a serial port.  The
 * PID is saved so the process can be terminated when the library unloads.
 */
static pid_t socat_pid = -1;
/*
 * Copies of the TTY and socket paths used when spawning the socat helper.
 * They are kept so the process can be restarted automatically if it exits.
 */
static char *socat_tty_path = NULL;
static char *socat_socket_path = NULL;

/* Track which file descriptors correspond to I²C devices and current address. */
static _Atomic int is_i2c_fd[FD_LIMIT];
static _Atomic int current_addr[FD_LIMIT]; // -1 if unknown

/* Resolve the real libc symbol addresses the first time we need them. */
static void ensure_resolved(void) {
    if (real_open && real_open64 && real_openat && real_read && real_write &&
        real_ioctl && real_close) return;
    real_open   = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_read   = dlsym(RTLD_NEXT, "read");
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

/*
 * Spawn the socat helper that bridges the configured TTY to a Unix domain
 * socket.  The helper uses the path information stored in
 * socat_tty_path/socat_socket_path and the resulting child PID is saved in
 * socat_pid so it can be monitored and terminated later.  This function is
 * used during initialization and whenever the helper needs to be restarted.
 */
static void spawn_socat(void) {
    if (!socat_tty_path || !*socat_tty_path) return; /* no helper requested */

    in_hook++; /* avoid intercepting our own calls in the child */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process: construct socat arguments and replace ourselves. */
        char listen_spec[512];
        char open_spec[512];
        snprintf(listen_spec, sizeof(listen_spec),
                 "UNIX-LISTEN:%s,fork,mode=777", socat_socket_path);
        /*
         * Use a PTY link so socat will create the pseudo terminal device if it
         * does not already exist.  The 'link' option ensures the allocated pty
         * is symlinked to the requested path, allowing the caller to open it
         * even when the node was missing before the helper started.
         */
        snprintf(open_spec, sizeof(open_spec),
                 "PTY,link=%s,raw,echo=0,b115200", socat_tty_path);
        /* Invoke socat from a fixed location so the correct helper is used. */
        execl(SOCAT_BINARY, "socat", listen_spec, open_spec, (char *)NULL);
        _exit(1); /* execl only returns on error */
    } else if (pid > 0) {
        /* Parent: remember the PID so we can monitor/cleanup. */
        socat_pid = pid;
    } else {
        /* Fork failed; ensure pid stays negative so future calls retry. */
        socat_pid = -1;
    }
    in_hook--;
}

/*
 * Verify that the socat helper is running.  If the process has exited or was
 * never started, spawn it again.  This allows the library to automatically
 * recover if the helper crashes or the serial device temporarily disappears.
 */
static void ensure_socat(void) {
    if (!socat_tty_path) return; /* helper never requested */

    if (socat_pid > 0) {
        /* Non-blocking check whether the child is still alive. */
        pid_t r = waitpid(socat_pid, NULL, WNOHANG);
        if (r == 0) return; /* still running */
    }

    /* Either the helper died or was never started: attempt to spawn it. */
    spawn_socat();
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

    /* Before attempting to send any data ensure the socat helper is alive so
     * external serial redirects remain functional. */
    ensure_socat();

    if (sock_fd < 0) ensure_socket();
    if (sock_fd < 0) return;

    ssize_t off = 0;
    while ((size_t)off < len) {
        ssize_t n = send(sock_fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += n;
            continue;
        }
        if (n < 0 && (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN)) {
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

/*
 * Helper for raw mode that sends a binary frame.  The frame format is
 * [addr][cmd][len][data...] where `cmd` is 0 for writes and 1 for reads.  Only
 * the first 255 bytes of the payload are sent since the length is encoded in a
 * single byte.  This mirrors the framing used by the serial tap helpers so the
 * receive side can forward the data without additional parsing.
 */
static void emit_raw_frame(int addr, int cmd, const unsigned char *data,
                           size_t len) {
    unsigned char hdr[3];
    if (len > 255) len = 255;
    hdr[0] = (unsigned char)addr;
    hdr[1] = (unsigned char)cmd;
    hdr[2] = (unsigned char)len;
    send_all_or_drop((const char *)hdr, sizeof(hdr));
    if (len > 0) {
        send_all_or_drop((const char *)data, len);
    }
}

// --- JSON logging helpers -------------------------------------------------
/*
 * The original implementation embedded large printf-style JSON format strings
 * directly at each call site.  That made the control flow harder to read and
 * obscured the intent of the surrounding logic.  The helpers below centralize
 * all JSON construction so higher level hooks simply invoke a small function
 * with well named parameters.
 */

/* Emit an \"open\" event describing the file descriptor and path. */
static void log_open_event(int fd, const char *path) {
    emitf("{\"type\":\"open\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"path\":\"%s\"}",
          getpid(), now_ns(), fd, path);
}

/* Emit a \"close\" event when an I\u00b2C descriptor is closed. */
static void log_close_event(int fd) {
    emitf("{\"type\":\"close\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d}",
          getpid(), now_ns(), fd);
}

/* Emit a \"write\" event including optional data payload. */
static void log_write_event(int fd, int addr, size_t len,
                            const char *data_hex, int truncated) {
    emitf("{\"type\":\"write\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"addr\":%d,\"len\":%zu,\"data_hex\":\"%s\"}%s",
          getpid(), now_ns(), fd, addr, len, data_hex,
          (truncated ? " /*truncated*/" : ""));
}

/* Emit header line for an I2C_RDWR ioctl event. */
static void log_rdwr_start(int fd, int nmsgs, long long ts) {
    emitf("{\"type\":\"ioctl_rdwr\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"nmsgs\":%d,\"detail\":[",
          getpid(), ts, fd, nmsgs);
}

/* Emit a single message element within an I2C_RDWR ioctl event. */
static void log_rdwr_msg(int idx, const struct i2c_msg *m, int last) {
    emitf("{\"idx\":%d,\"addr\":%u,\"flags\":%u,\"len\":%u,", idx, m->addr, m->flags, m->len);
    if (m->flags & I2C_M_RD) {
        emitf("\"dir\":\"read\"}%s", (last ? "" : ","));
    } else {
        size_t take = m->len > 8192 ? 8192 : m->len;
        char *hex = malloc(take*2 + 1);
        if (hex) {
            hex_encode(hex, (const unsigned char*)m->buf, take);
            emitf("\"dir\":\"write\",\"data_hex\":\"%s\"}%s", hex, (last ? "" : ","));
            free(hex);
        } else {
            emitf("\"dir\":\"write\",\"data_hex\":\"\"}%s", (last ? "" : ","));
        }
    }
}

/* Terminate an I2C_RDWR ioctl event. */
static void log_rdwr_end(void) {
    emitf("]}");
}

/* Emit an event describing a slave address change ioctl. */
static void log_ioctl_set_slave(int fd, unsigned long addr, int force) {
    emitf("{\"type\":\"ioctl_set_slave\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"addr\":%lu,\"force\":%s}",
          getpid(), now_ns(), fd, addr, (force ? "true" : "false"));
}

/* Emit an event describing a generic SMBus ioctl. */
static void log_ioctl_smbus(int fd, const struct i2c_smbus_ioctl_data *sd) {
    emitf("{\"type\":\"ioctl_smbus\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"read\":%s,\"command\":%u,\"size\":%u}",
          getpid(), now_ns(), fd,
          (sd->read_write == I2C_SMBUS_READ ? "true" : "false"),
          sd->command, sd->size);
}

/* Emit an event for any other ioctl commands that are not specially handled. */
static void log_ioctl_other(int fd, unsigned long req) {
    emitf("{\"type\":\"ioctl_other\",\"pid\":%d,\"ts_ns\":%lld,\"fd\":%d,\"req\":%lu}",
          getpid(), now_ns(), fd, req);
}

// --- init
/* Constructor that initializes environment-derived settings. */
__attribute__((constructor))
static void init_i2c_redirect(void) {
    ensure_resolved();

    const char *p = getenv("I2C_PROXY_PASSTHROUGH");
    passthrough = (p && *p && strcmp(p, "0") != 0) ? 1 : 0;

    const char *raw = getenv("I2C_PROXY_RAW");
    raw_mode = (raw && *raw && strcmp(raw, "0") != 0) ? 1 : 0;

    const char *fd_str = getenv("I2C_PROXY_SOCK_FD");
    if (fd_str && *fd_str) {
        char *end = NULL;
        long v = strtol(fd_str, &end, 10);
        if (end && *end == '\0' && v >= 0 && v < 1<<30) sock_fd_from_env = (int)v;
    }
    const char *sp = getenv("I2C_PROXY_SOCK");
    if (sp && *sp) sock_path = strdup(sp);

    /*
     * Optional serial redirection: if I2C_SOCAT_TTY is provided spawn a socat
     * helper that connects a Unix domain socket to the given TTY.  The helper
     * allows external tools to talk to the serial device using the same JSON
     * protocol as the proxy socket.  We remember the child PID for cleanup.
     */
    const char *tty = getenv("I2C_SOCAT_TTY");
    if (tty && *tty) {
        const char *sock = getenv("I2C_SOCAT_SOCKET");
        /*
         * If the helper's socket path isn't specified default to
         * /tmp/ttyS22.tap.sock so all components agree on a common
         * location.
         */
        if (!sock || !*sock) sock = "/tmp/ttyS22.tap.sock";

        /* Remember the paths so the helper can be restarted if it dies. */
        socat_tty_path = strdup(tty);
        socat_socket_path = strdup(sock);

        /* Spawn the initial socat helper.  Later sends will verify that it is
         * still running and restart it if necessary. */
        spawn_socat();
    }
}

/*
 * Destructor invoked when the shared library is unloaded.  If a socat helper
 * was spawned in init_i2c_redirect(), terminate it so no stray processes are
 * left running once the host program exits.  The function also closes any
 * proxy socket and frees duplicated strings to avoid leaking resources.
 */
__attribute__((destructor))
static void deinit_i2c_redirect(void) {
    if (socat_pid > 0) {
        kill(socat_pid, SIGTERM);
        waitpid(socat_pid, NULL, 0);
    }
    /* Close the forwarding socket if it was ever opened to avoid leaks. */
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
    /* Free the duplicated socket path allocated during initialization. */
    free(sock_path);
    /* Free any duplicated path strings used for the socat helper. */
    free(socat_tty_path);
    free(socat_socket_path);
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
        log_open_event(fd, path);
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
        log_open_event(fd, path);
    }
    return fd;
}

// --- close
int close(int fd) {
    ensure_resolved();
    if (is_marked_i2c(fd)) {
        log_close_event(fd);
        mark_i2c_fd(fd, 0);
    }
    in_hook++;
    int r = real_close(fd);
    in_hook--;
    return r;
}

// --- read
/*
 * Hook for the read syscall that retrieves data from the proxy socket when
 * an intercepted I²C descriptor attempts to read.  This allows companion
 * tools like `tty_tap_server` to feed responses back to the client program
 * without touching real hardware.  When passthrough is enabled the call is
 * forwarded to the real `read` implementation so that genuine I²C devices are
 * accessed normally.
 */
ssize_t read(int fd, void *buf, size_t count) {
    ensure_resolved();
    if (in_hook) return real_read(fd, buf, count);

    if (is_marked_i2c(fd)) {
        if (passthrough) {
            in_hook++; ssize_t r = real_read(fd, buf, count); in_hook--; return r;
        }

        /*
         * When not talking to real hardware, pull data from the proxy socket.
         * This mirrors the behavior of the write hook which pushes traffic out
         * on the same connection.  If no socket is available, return EOF so the
         * caller can retry later.
         */
        ensure_socat();
        if (sock_fd < 0) ensure_socket();
        if (sock_fd < 0) return 0;

        ssize_t n = recv(sock_fd, buf, count, 0);
        return n;
    }

    in_hook++; ssize_t r = real_read(fd, buf, count); in_hook--; return r;
}

// --- write
/* Hook for the write syscall that logs data written to I²C descriptors. */
ssize_t write(int fd, const void *buf, size_t count) {
    ensure_resolved();
    if (in_hook) return real_write(fd, buf, count);

    if (is_marked_i2c(fd)) {
        int addr = -1;
        if (fd >= 0 && fd < FD_LIMIT) addr = atomic_load(&current_addr[fd]);

        if (raw_mode) {
            /* In raw mode forward the payload as a binary frame. */
            emit_raw_frame(addr, 0, (const unsigned char *)buf, count);
        } else {
            /* Otherwise log the transfer as JSON with a hex encoded body. */
            const size_t max_dump = 8192;
            size_t n = count > max_dump ? max_dump : count;
            char *hex = malloc(n * 2 + 1);
            if (hex) {
                hex_encode(hex, (const unsigned char *)buf, n);
                log_write_event(fd, addr, count, hex, (count>max_dump));
                free(hex);
            }
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
    log_rdwr_start(fd, (int)d->nmsgs, ts);
    for (int i = 0; i < (int)d->nmsgs; i++) {
        struct i2c_msg *m = &d->msgs[i];
        log_rdwr_msg(i, m, i + 1 >= (int)d->nmsgs);
    }
    log_rdwr_end();
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
        log_ioctl_set_slave(fd, addr, (req==I2C_SLAVE_FORCE));
        if (passthrough) {
            in_hook++; ret = real_ioctl(fd, req, addr); in_hook--; 
        } else ret = 0;
        return ret;
    }

    if (req == I2C_RDWR) {
        struct i2c_rdwr_ioctl_data *d = va_arg(ap, struct i2c_rdwr_ioctl_data *);
        va_end(ap);
        if (d) {
            if (raw_mode) {
                /* Send each message as a binary frame to mirror on-the-wire
                 * traffic. */
                for (int i = 0; i < (int)d->nmsgs; i++) {
                    struct i2c_msg *m = &d->msgs[i];
                    int cmd = (m->flags & I2C_M_RD) ? 1 : 0;
                    emit_raw_frame(m->addr, cmd,
                                   (const unsigned char *)m->buf, m->len);
                }
            } else {
                log_i2c_rdwr(fd, d);
            }
        }
        if (passthrough) { in_hook++; ret = real_ioctl(fd, req, d); in_hook--; } else ret = 0;
        return ret;
    }

    if (req == I2C_SMBUS) {
        struct i2c_smbus_ioctl_data *sd = va_arg(ap, struct i2c_smbus_ioctl_data *);
        va_end(ap);
        if (sd) {
            log_ioctl_smbus(fd, sd);
        }
        if (passthrough) { in_hook++; ret = real_ioctl(fd, req, sd); in_hook--; } else ret = 0;
        return ret;
    }


    void *arg = va_arg(ap, void *);
    va_end(ap);
    log_ioctl_other(fd, req);
    if (passthrough) { in_hook++; ret = real_ioctl(fd, req, arg); in_hook--; } else ret = 0;
    return ret;
}
