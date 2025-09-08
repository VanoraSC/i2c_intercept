/*
 * i2c_redirect.c
 * ---------------
 * LD_PRELOAD library that intercepts common I²C related syscalls and emits
 * raw binary frames describing the traffic to a Unix domain socket.  All
 * intercepted operations are proxied and never reach real hardware, allowing
 * the caller to observe bus traffic without affecting physical devices.
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
#include <pthread.h> /* For pthread_mutex_t used to serialize I/O */
#include <poll.h>    /* For intercepting poll on virtual I²C descriptors */

#ifndef FD_LIMIT
#define FD_LIMIT 4096
#endif

/*
 * Absolute path to the socat binary used when bridging I²C traffic to a
 * serial device.  Using a fixed path avoids relying on the invoking process'
 * PATH environment and ensures the intended helper is executed.
 */
#define SOCAT_BINARY "/media/data/socat"

/*
 * Opcode placed in the second byte of the ten-byte frame to request that the
 * tap server perform a read and return data. The remaining eight bytes of the
 * frame are ignored for such requests.
 */
#define READ_COMMAND 0x01  /* Opcode used by the tap server for reads */

// --- real syscalls
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static ssize_t (*real_write)(int, const void *, size_t) = NULL;
static int (*real_ioctl)(int, unsigned long, ...) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_poll)(struct pollfd *, nfds_t, int) = NULL;

/* Guard to avoid recursively intercepting our own syscalls. */
static _Thread_local int in_hook = 0;

/* Socket management state: either connect to a path or use an existing FD. */
static int sock_fd = -1;
static int sock_fd_from_env = -1;
static char *sock_path = NULL;

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

/*
 * Global mutex that serializes intercepted read() and write() operations.
 * Multiple threads may perform I²C I/O concurrently and the mutex prevents
 * their traffic from interleaving, preserving the integrity of the captured
 * stream.
 */
pthread_mutex_t i2c_io_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The previous implementation buffered framed responses from the tap server.
 * The protocol has since been simplified so that each read operation expects a
 * fixed 62‑byte payload without any intermediate buffering.  As a result the
 * dedicated read buffer is no longer required and has been removed. */

/*
 * Table of I²C addresses that should bypass the redirect logic.  Each index
 * corresponds to a 7‑ or 10‑bit address and is set when the address appears in
 * the comma separated list provided via the I2C_REDIRECT_EXEMPT environment
 * variable.  Addresses marked here are passed through to the real kernel I²C
 * implementation instead of being forwarded to the proxy socket.
 */
static unsigned char exempt_addrs[1024];

/* Parse the I2C_REDIRECT_EXEMPT environment variable into the lookup table. */
static void parse_exempt_env(void) {
    const char *list = getenv("I2C_REDIRECT_EXEMPT");
    if (!list || !*list) return;
    char *copy = strdup(list);             /* strtok_r() needs a writable copy */
    char *tok, *save = NULL;
    for (tok = strtok_r(copy, ", ", &save); tok; tok = strtok_r(NULL, ", ", &save)) {
        int base = 10;                     /* decimal unless prefixed by 0x */
        if (tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
            base = 16;
        }
        char *end;
        long v = strtol(tok, &end, base);  /* parse the token into an address */
        if (*end == '\0' &&
            v >= 0 && v < (long)(sizeof(exempt_addrs) / sizeof(exempt_addrs[0]))) {
            exempt_addrs[v] = 1;           /* mark address as exempt when valid */
        }
    }
    free(copy);
}

/* Return non‑zero when the given address should bypass the redirect. */
static int is_exempt_addr(int addr) {
    if (addr >= 0 && addr < (int)(sizeof(exempt_addrs) / sizeof(exempt_addrs[0]))) {
        return exempt_addrs[addr] != 0;
    }
    return 0;
}

/* Resolve the real libc symbol addresses the first time we need them. */
static void ensure_resolved(void) {
    if (real_open && real_open64 && real_openat && real_read && real_write &&
        real_ioctl && real_close && real_poll) return;
    real_open   = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_read   = dlsym(RTLD_NEXT, "read");
    real_write  = dlsym(RTLD_NEXT, "write");
    real_ioctl  = dlsym(RTLD_NEXT, "ioctl");
    real_close  = dlsym(RTLD_NEXT, "close");
    real_poll   = dlsym(RTLD_NEXT, "poll");
}

/* Removed helpers for time and hex encoding since only raw forwarding remains. */

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

/* Emit a debugging trace message when the I2C_PROXY_TRACE environment
 * variable is set.  Logging is routed to stderr so it does not interfere
 * with the standard output of the intercepted application.  The in_hook
 * guard temporarily disables syscall interception to avoid recursive
 * logging when vfprintf itself issues write calls.
 */
static void trace_log(const char *fmt, ...) {
    if (!getenv("I2C_PROXY_TRACE")) return;
    in_hook++;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    in_hook--;
}

// --- socket connect & send (with retry)
/*
 * Connect to the proxy Unix socket, returning the new fd or -1 on error.
 * The socket is configured in non-blocking mode so future sends will fail
 * fast rather than stalling the intercepted process when the peer stops
 * draining data.
 */
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
    /* Put the socket into non-blocking mode so later sends return immediately
     * if the receiver stops consuming data.  Errors here are ignored since the
     * socket will simply remain blocking, restoring the previous behavior. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
 * Send len bytes over the proxy socket in non-blocking mode.  When the socket
 * buffer fills up the remaining bytes are discarded so the intercepted
 * process never blocks on slow or absent readers.  A single reconnection
 * attempt is made on connection related errors.
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
        ssize_t n = send(sock_fd, buf + off, len - off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
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
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /*
             * The send buffer is full; drop the remaining bytes to avoid
             * blocking the application.  This mirrors the behavior of many
             * tracing tools which sacrifice data when the consumer falls
             * behind.
             */
            return;
        }
        return; /* other error or zero write -> drop */
    }
}

/* Previous JSON helpers removed: the library now speaks only raw frames. */
/*
 * Helper for raw mode that sends a binary frame.  Frames are formatted as
 * `[addr][cmd][d0]...[d7]` and therefore always occupy ten bytes.  The `cmd`
 * byte conveys whether the payload represents a write (0) or a read request
 * (`READ_COMMAND`).  All eight payload bytes are transmitted for writes so the
 * tap server can observe the original data.  Read requests ignore the payload
 * contents entirely and are typically filled with zeros.  Payloads shorter than
 * eight bytes are padded with zeros while longer payloads are truncated to keep
 * the frame size fixed.
 */
static void emit_raw_frame(int addr, int cmd, const unsigned char *data,
                           size_t len) {
    unsigned char frame[10];
    frame[0] = (unsigned char)addr;      /* Target I²C address */
    frame[1] = (unsigned char)cmd;       /* Operation code */

    /* Copy up to eight data bytes and pad the remainder with zeros. */
    size_t copy = (len > 8) ? 8 : len;
    if (copy > 0 && data) {
        memcpy(&frame[2], data, copy);
    }
    if (copy < 8) {
        memset(&frame[2 + copy], 0, 8 - copy);
    }

    /* Send the fixed-length frame to the tap server. */
    send_all_or_drop((const char *)frame, sizeof(frame));
}
/* The library now emits only raw frames; previous JSON helpers were removed. */

// --- init
/* Constructor that initializes environment-derived settings. */
__attribute__((constructor))
static void init_i2c_redirect(void) {
    ensure_resolved();
    /* Populate the address exclusion table before any I²C traffic occurs. */
    parse_exempt_env();

    const char *fd_str = getenv("I2C_PROXY_SOCK_FD");
    if (fd_str && *fd_str) {
        char *end = NULL;
        long v = strtol(fd_str, &end, 10);
        if (end && *end == '\0' && v >= 0 && v < 1<<30) sock_fd_from_env = (int)v;
    }
    const char *sp = getenv("I2C_PROXY_SOCK");
    const char *tty = getenv("I2C_SOCAT_TTY");
    const char *sock = getenv("I2C_SOCAT_SOCKET");

    /*
     * Apply defaults so callers do not need to set environment variables for
     * the common configuration.  The serial helper mirrors the defaults used by
     * the helper scripts: `/dev/ttyS22` for the device and
     * `/tmp/ttyS22.tap.sock` for the Unix socket.  The proxy socket path follows
     * the helper's socket when present, otherwise it falls back to the generic
     * `/tmp/i2c.tap.sock` location.
     */
    if (!tty || !*tty) tty = "/dev/ttyS22";
    if (!sock || !*sock) sock = "/tmp/ttyS22.tap.sock";
    if (!sp || !*sp) sp = sock;
    sock_path = strdup(sp);

    /* Remember paths so the helper can be restarted if it dies. */
    socat_tty_path = strdup(tty);
    socat_socket_path = strdup(sock);

    /* Spawn the initial socat helper.  Later sends will verify that it is still
     * running and restart it if necessary. */
    spawn_socat();
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
    }
    return fd;
}

int open(const char *path, int flags, ...) {
    /* Trace the open attempt so descriptor creation can be followed. */
    trace_log("open path=%s flags=0x%x", path, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        return handle_open_common(path, flags, &mode, 0);
    }
    return handle_open_common(path, flags, NULL, 0);
}

int open64(const char *path, int flags, ...) {
    /* Trace the open64 attempt for debugging purposes. */
    trace_log("open64 path=%s flags=0x%x", path, flags);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
        return handle_open_common(path, flags, &mode, 1);
    }
    return handle_open_common(path, flags, NULL, 1);
}

int openat(int dirfd, const char *path, int flags, ...) {
    /* Trace the openat invocation including the directory file descriptor. */
    trace_log("openat dirfd=%d path=%s flags=0x%x", dirfd, path, flags);
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
    }
    return fd;
}

// --- close
int close(int fd) {
    /* Trace descriptor closure to help follow resource lifetimes. */
    trace_log("close fd=%d", fd);
    ensure_resolved();
    if (is_marked_i2c(fd)) {
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
 * without touching real hardware.
 */
ssize_t read(int fd, void *buf, size_t count) {
    /* Trace read attempts along with the requested byte count. */
    trace_log("read fd=%d count=%zu", fd, count);
    ensure_resolved();
    if (in_hook) return real_read(fd, buf, count);

    /*
     * Serialize all intercepted read operations.  This prevents multiple
     * threads from interleaving I²C traffic which could corrupt the captured
     * stream or produce confusing logs.
     */
    pthread_mutex_lock(&i2c_io_mutex);

    ssize_t r = 0;

    if (is_marked_i2c(fd)) {
        int addr = -1;
        if (fd >= 0 && fd < FD_LIMIT) addr = atomic_load(&current_addr[fd]);
        if (is_exempt_addr(addr)) {
            in_hook++; r = real_read(fd, buf, count); in_hook--; goto out;
        }

        /* All redirected reads are satisfied by the tap server.  The new
         * protocol conveys a read request using a single 10‑byte frame that
         * contains the target address, the read command opcode and eight bytes
         * of padding.  Once this frame is sent the server replies directly with
         * a fixed 62‑byte payload. */
        ensure_socat();
        if (sock_fd < 0) ensure_socket();
        if (sock_fd < 0) { r = 0; goto out; }

        /* Emit the read command frame.  The payload carries no useful data but
         * is padded with zeros to satisfy the fixed frame size. */
        unsigned char pad[8] = {0};
        emit_raw_frame(addr, READ_COMMAND, pad, sizeof(pad));

        /* Read exactly 62 bytes of payload, aborting if the data does not
         * arrive within 100ms.  Any surplus bytes requested by the caller are
         * truncated to this fixed payload size. */
        unsigned char data[62];
        size_t got = 0;
        while (got < sizeof(data)) {
            struct pollfd pfd = { sock_fd, POLLIN, 0 };
            if (poll(&pfd, 1, 100) <= 0) { r = 0; goto out; }
            ssize_t n = recv(sock_fd, data + got, sizeof(data) - got, 0);
            if (n <= 0) { r = n; goto out; }
            got += (size_t)n;
        }

        size_t copy = (count < sizeof(data)) ? count : sizeof(data);
        memcpy(buf, data, copy);
        r = (ssize_t)copy;
        goto out;
    }

    /* Non-I²C descriptors simply call through to the real read(). */
    in_hook++; r = real_read(fd, buf, count); in_hook--;

out:
    pthread_mutex_unlock(&i2c_io_mutex);
    return r;
}

// --- poll
/*
 * Applications often rely on poll() to wait for I²C transactions to
 * complete.  The descriptors exposed by this library are not backed by real
 * hardware and therefore never become readable.  This hook redirects poll()
 * requests to the proxy socket so callers observe readiness once the tap
 * server has provided a response.
 */
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    /* Trace poll usage for debugging purposes. */
    trace_log("poll nfds=%zu timeout=%d", (size_t)nfds, timeout);
    ensure_resolved();
    if (in_hook) return real_poll(fds, nfds, timeout);

    for (nfds_t i = 0; i < nfds; i++) {
        if (is_marked_i2c(fds[i].fd)) {
            int addr = -1;
            if (fds[i].fd >= 0 && fds[i].fd < FD_LIMIT)
                addr = atomic_load(&current_addr[fds[i].fd]);
            if (is_exempt_addr(addr)) {
                return real_poll(fds, nfds, timeout);
            }
            ensure_socat();
            if (sock_fd < 0) ensure_socket();
            if (sock_fd < 0) {
                fds[i].revents = 0;
                return 0; /* no connection, so no events */
            }
            struct pollfd p = { sock_fd, fds[i].events, 0 };
            int r = real_poll(&p, 1, timeout);
            fds[i].revents = p.revents;
            return r;
        }
    }

    return real_poll(fds, nfds, timeout);
}

// --- write
/* Hook for the write syscall that logs data written to I²C descriptors. */
ssize_t write(int fd, const void *buf, size_t count) {
    /* Trace write attempts so payload sizes can be observed. */
    trace_log("write fd=%d count=%zu", fd, count);
    ensure_resolved();
    if (in_hook) return real_write(fd, buf, count);

    /* Guard the critical section so concurrent writes do not interleave. */
    pthread_mutex_lock(&i2c_io_mutex);

    ssize_t r = 0;

    if (is_marked_i2c(fd)) {
        int addr = -1;
        if (fd >= 0 && fd < FD_LIMIT) addr = atomic_load(&current_addr[fd]);
        if (is_exempt_addr(addr)) {
            in_hook++; r = real_write(fd, buf, count); in_hook--; goto out;
        }
        /* Forward the payload as a binary frame. */
        emit_raw_frame(addr, 0, (const unsigned char *)buf, count);
        r = (ssize_t)count;
        goto out;
    }

    in_hook++;
    r = real_write(fd, buf, count);
    in_hook--;

out:
    pthread_mutex_unlock(&i2c_io_mutex);
    return r;
}

// --- ioctl
/* Main ioctl hook that handles several I²C-specific requests. */
int ioctl(int fd, unsigned long req, ...) {
    /* Trace ioctl usage including the raw request code. */
    trace_log("ioctl fd=%d req=0x%lx", fd, req);
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

    if (req == I2C_SLAVE || req == I2C_SLAVE_FORCE) {
        unsigned long addr = va_arg(ap, unsigned long);
        va_end(ap);
        if (fd >= 0 && fd < FD_LIMIT) atomic_store(&current_addr[fd], (int)addr);
        if (is_exempt_addr((int)addr)) {
            in_hook++;
            int r = real_ioctl(fd, req, addr);
            in_hook--;
            return r;
        }
        /* Suppress the real call for redirected addresses. */
        return 0;
    }

    if (req == I2C_RDWR) {
        struct i2c_rdwr_ioctl_data *d = va_arg(ap, struct i2c_rdwr_ioctl_data *);
        va_end(ap);
        if (d) {
            bool all_exempt = true;
            for (int i = 0; i < (int)d->nmsgs; i++) {
                if (!is_exempt_addr(d->msgs[i].addr)) { all_exempt = false; break; }
            }
            if (all_exempt) {
                in_hook++;
                int r = real_ioctl(fd, req, d);
                in_hook--;
                return r;
            }
            /* Send each message as a binary frame to mirror on-the-wire traffic. */
            for (int i = 0; i < (int)d->nmsgs; i++) {
                struct i2c_msg *m = &d->msgs[i];
                int cmd = (m->flags & I2C_M_RD) ? 1 : 0;
                emit_raw_frame(m->addr, cmd,
                               (const unsigned char *)m->buf, m->len);
            }
        }
        /* The real I/O is suppressed; report success to the caller. */
        return 0;
    }

    if (req == I2C_SMBUS) {
        struct i2c_smbus_ioctl_data *sd = va_arg(ap, struct i2c_smbus_ioctl_data *);
        va_end(ap);
        (void)sd; /* Request acknowledged but no further action taken. */
        return 0;
    }

    (void)va_arg(ap, void *);
    va_end(ap);
    /* Unknown requests on I²C descriptors are acknowledged but not forwarded. */
    return 0;
}
