#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>

#define TTY_PATH "/dev/ttyS22"
#define DEFAULT_SOCK_PATH "/tmp/i2c.tap.sock"

static int redirect_addr[128];

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
        tty.c_cc[VTIME] = 5; // 0.5s
        tcsetattr(fd, TCSANOW, &tty);
    }
    return fd;
}

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

static void hex2bin(const char *hex, unsigned char *out, size_t *out_len) {
    size_t len = strlen(hex) / 2;
    for (size_t i=0;i<len;i++) {
        unsigned int byte;
        sscanf(hex + 2*i, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
    *out_len = len;
}

static void forward_write(int tty_fd, int addr, const char *hex) {
    if (!redirect_addr[addr]) return;
    unsigned char buf[4096];
    size_t data_len;
    hex2bin(hex, buf+2, &data_len);
    buf[0] = (unsigned char)addr;
    buf[1] = 0; // write command
    ssize_t w = write(tty_fd, buf, data_len + 2);
    (void)w;
}

static void forward_read(int tty_fd, int addr, const char *hex) {
    if (!redirect_addr[addr]) return;
    unsigned char buf[4096];
    size_t data_len;
    hex2bin(hex, buf+2, &data_len);
    buf[0] = (unsigned char)addr;
    buf[1] = 1; // read command
    ssize_t w = write(tty_fd, buf, data_len + 2);
    (void)w;
}

int main(void) {
    parse_addr_env();
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
    close(tty_fd);
    close(sock_fd);
    return 0;
}
