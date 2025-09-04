/*
 * i2c_tty_redirect.c
 * -------------------
 * Utility that taps into the stream produced by the I²C redirect library and
 * forwards selected transactions to a serial TTY. Bytes coming back from the
 * TTY are framed and written back to the socket so the proxy can simulate
 * responses. All communication is framed as `[addr][cmd][len][data...]` where
 * `cmd` is 0 for a write and 1 for a read. By default messages are exchanged as
 * JSON lines, but when the `I2C_PROXY_RAW` environment variable is set the
 * program bypasses the JSON layer and relays the binary frames directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

/* Serial device used for forwarding and default socket path to the proxy. */
#define TTY_PATH "/dev/ttyS22"
#define DEFAULT_SOCK_PATH "/tmp/i2c.tap.sock"

/* Bitmap of which 7-bit I²C addresses should be forwarded. */
static int redirect_addr[128];
/* When non-zero, forward raw binary frames instead of JSON messages. */
static int raw_mode = 0;

/*
 * Parse the I2C_TTY_ADDRS environment variable which contains a comma
 * separated list of decimal or hexadecimal addresses. Any address present is
 * marked in the redirect_addr array so only traffic for those devices is
 * forwarded to the serial line.
 */
static void parse_addr_env(void) {
    const char *env = getenv("I2C_TTY_ADDRS");
    if (!env || !*env) return;
    char *copy = strdup(env);
    char *tok = strtok(copy, ",");
    while (tok) {
        char *end = NULL;
        long v = strtol(tok, &end, 0);
        if (end && *end == '\0' && v >=0 && v < 128) {
            redirect_addr[v] = 1;
        }
        tok = strtok(NULL, ",");
    }
    free(copy);
}

/*
 * Open and configure the serial port. The port is set to 115200 baud and
 * basic 8N1 settings with minimal processing so raw bytes can be transferred.
 */
static int open_tty(void) {
    int fd = open(TTY_PATH, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) return -1;
    struct termios tty;
    if (tcgetattr(fd, &tty) == 0) {
        cfsetospeed(&tty, B115200);
        cfsetispeed(&tty, B115200);
        tty.c_cflag &= ~PARENB;
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CSIZE;
        tty.c_cflag |= CS8;
        tty.c_cflag &= ~CRTSCTS;
        tty.c_cflag |= CREAD | CLOCAL;
        tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
        tty.c_iflag &= ~(IXON | IXOFF | IXANY);
        tty.c_oflag &= ~OPOST;
        tty.c_cc[VMIN]  = 1;
        tty.c_cc[VTIME] = 5; /* 0.5s timeout */
        tcsetattr(fd, TCSANOW, &tty);
    }
    return fd;
}

/* Connect to the JSON stream socket used by the I²C redirect library. */
static int connect_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, path, sizeof(sa.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Convert a hex string into bytes. */
static void hex2bin(const char *hex, unsigned char *out, size_t *out_len) {
    size_t len = strlen(hex) / 2;
    for (size_t i=0;i<len;i++) {
        unsigned int byte;
        sscanf(hex + 2*i, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
    *out_len = len;
}

/*
 * Frame a write command and push it to the serial port. The payload is
 * prefixed by address, command byte and length.
 */
static void forward_write(int tty_fd, int addr, const char *hex) {
    if (!redirect_addr[addr]) return;
    unsigned char buf[4096];
    size_t data_len;
    hex2bin(hex, buf+3, &data_len);
    if (data_len > 255) data_len = 255;
    buf[0] = (unsigned char)addr;
    buf[1] = 0; /* write command */
    buf[2] = (unsigned char)data_len;
    ssize_t w = write(tty_fd, buf, data_len + 3);
    (void)w;
}

/*
 * Same as forward_write but marks the command as a read operation. This allows
 * the serial side to distinguish the direction of the transfer.
 */
static void forward_read(int tty_fd, int addr, const char *hex) {
    if (!redirect_addr[addr]) return;
    unsigned char buf[4096];
    size_t data_len;
    hex2bin(hex, buf+3, &data_len);
    if (data_len > 255) data_len = 255;
    buf[0] = (unsigned char)addr;
    buf[1] = 1; /* read command */
    buf[2] = (unsigned char)data_len;
    ssize_t w = write(tty_fd, buf, data_len + 3);
    (void)w;
}

/* Convert bytes to a hex string. Used when relaying data back to the socket. */
static void bin2hex(const unsigned char *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2] = hex[(in[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[in[i] & 0xF];
    }
    out[len*2] = '\0';
}

/* Read exactly len bytes from fd unless an error occurs. */
static ssize_t read_full(int fd, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return (ssize_t)off;
}

struct relay_arg {
    int tty_fd;
    int sock_fd;
};

/*
 * Background thread that relays framed responses from the serial line back to
 * the I²C proxy socket. Each frame read from the TTY is turned into a JSON
 * line and written out so the proxy can feed it to interested clients.
 */
static void *relay_tty_to_sock(void *arg) {
    struct relay_arg *a = (struct relay_arg *)arg;
    unsigned char data[256];
    unsigned char hdr[3];
    char hex[512];
    char line[1024];
    while (1) {
        if (read_full(a->tty_fd, hdr, 3) < 0) break;
        int addr = hdr[0];
        int cmd = hdr[1];
        int len = hdr[2];
        if (len < 0 || len > 255) break;
        if (read_full(a->tty_fd, data, (size_t)len) < 0) break;
        if (!redirect_addr[addr]) continue;
        if (raw_mode) {
            /* Raw mode: forward the frame as-is to the socket. */
            if (write(a->sock_fd, hdr, 3) < 0) break;
            if (len > 0 && write(a->sock_fd, data, (size_t)len) < 0) break;
        } else {
            bin2hex(data, (size_t)len, hex);
            int n = snprintf(line, sizeof(line),
                             "{\"type\":\"%s\",\"addr\":%d,\"len\":%d,\"data_hex\":\"%s\"}\n",
                             cmd ? "read" : "write", addr, len, hex);
            if (n > 0 && n < (int)sizeof(line)) {
                ssize_t off = 0;
                while (off < n) {
                    ssize_t w = write(a->sock_fd, line + off, (size_t)(n - off));
                    if (w <= 0) break;
                    off += w;
                }
            }
        }
    }
    return NULL;
}

/*
 * Entry point: connect to the proxy socket, launch the relay thread and forward
 * JSON messages describing I²C writes and reads to the serial port for any
 * address flagged in redirect_addr.
 */
int main(void) {
    parse_addr_env();
    const char *raw = getenv("I2C_PROXY_RAW");
    raw_mode = (raw && *raw && strcmp(raw, "0") != 0);
    const char *sock_path = getenv("I2C_PROXY_SOCK");
    if (!sock_path || !*sock_path) sock_path = DEFAULT_SOCK_PATH;
    int sock_fd = connect_socket(sock_path);
    if (sock_fd < 0) {
        perror("connect socket");
        return 1;
    }
    int tty_fd = open_tty();
    if (tty_fd < 0) {
        perror("open tty");
        return 1;
    }
    struct relay_arg arg = { tty_fd, sock_fd };
    pthread_t tid;
    if (pthread_create(&tid, NULL, relay_tty_to_sock, &arg) != 0) {
        perror("pthread_create");
        return 1;
    }
    if (raw_mode) {
        unsigned char hdr2[3];
        unsigned char data[256];
        while (1) {
            if (read_full(sock_fd, hdr2, 3) < 0) break;
            int addr = hdr2[0];
            int len = hdr2[2];
            if (len < 0 || len > 255) break;
            if (read_full(sock_fd, data, (size_t)len) < 0) break;
            if (!redirect_addr[addr]) continue;
            if (write(tty_fd, hdr2, 3) < 0) break;
            if (len > 0 && write(tty_fd, data, (size_t)len) < 0) break;
        }
    } else {
        FILE *fp = fdopen(sock_fd, "r");
        if (!fp) {
            perror("fdopen");
            return 1;
        }
        char line[65536];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "\"type\":\"write\"")) {
                char *p = strstr(line, "\"addr\":");
                if (!p) continue;
                int addr = strtol(p+8, NULL, 10);
                char *h = strstr(line, "\"data_hex\":\"");
                if (!h) continue;
                h += strlen("\"data_hex\":\"");
                char *end = strchr(h, '\"');
                if (!end) continue;
                *end = '\0';
                forward_write(tty_fd, addr, h);
            } else if (strstr(line, "\"type\":\"read\"")) {
                char *p = strstr(line, "\"addr\":");
                if (!p) continue;
                int addr = strtol(p+8, NULL, 10);
                char *h = strstr(line, "\"data_hex\":\"");
                if (!h) continue;
                h += strlen("\"data_hex\":\"");
                char *end = strchr(h, '\"');
                if (!end) continue;
                *end = '\0';
                forward_read(tty_fd, addr, h);
            }
        }
    }
    pthread_cancel(tid);
    pthread_join(tid, NULL);
    close(tty_fd);
    close(sock_fd);
    return 0;
}
