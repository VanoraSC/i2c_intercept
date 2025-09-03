#include "util.h"

const char     *DUMMY_PATH              = "/tmp/i2c-2";
const char     *I2C_PATH                = "/dev/i2c-2";  // TODO: make this configurable via env variable?
const char     *TTY_PATH                = "/dev/ttyS22"; // TODO: make this configurable via env variable?
int             tty_fd                  = -1;
uint8_t         fd_i2c_addr[FD_SETSIZE] = {0}; // how it looks: [0, some_i2c_addr 0x30, some_i2c_addr 0x31, ...]
LogLevel        log_level               = INFO;
pthread_mutex_t tty_mutex               = PTHREAD_MUTEX_INITIALIZER;

void print_zulu_time(void) {
    struct timeval tv;
    struct tm      tm_utc;
    char           buf[64];
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm_utc);
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ", tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec, tv.tv_usec);
    printf(COLOR_GRAY "%s " COLOR_RESET, buf);
}

void print_lib_name(void) { printf(COLOR_CYAN "i2c_intercept: " COLOR_RESET); }

void print_trace(const char *fmt, ...) {
    if (log_level <= TRACE) {
        va_list args;
        va_start(args, fmt);
        print_zulu_time();
        printf(COLOR_PURPLE "TRACE " COLOR_RESET);
        print_lib_name();
        vprintf(fmt, args);
        va_end(args);
    }
}

void print_debug(const char *fmt, ...) {
    if (log_level <= DEBUG) {
        va_list args;
        va_start(args, fmt);
        print_zulu_time();
        printf(COLOR_BLUE "DEBUG " COLOR_RESET);
        print_lib_name();
        vprintf(fmt, args);
        va_end(args);
    }
}

void print_info(const char *fmt, ...) {
    if (log_level <= INFO) {
        va_list args;
        va_start(args, fmt);
        print_zulu_time();
        printf(COLOR_GREEN " INFO " COLOR_RESET);
        print_lib_name();
        vprintf(fmt, args);
        va_end(args);
    }
}

void print_warning(const char *fmt, ...) {
    if (log_level <= WARN) {
        va_list args;
        va_start(args, fmt);
        print_zulu_time();
        printf(COLOR_YELLOW " WARN " COLOR_RESET);
        print_lib_name();
        vprintf(fmt, args);
        va_end(args);
    }
}

void print_critical(const char *fmt, ...) {
    if (log_level <= ERROR) {
        va_list args;
        va_start(args, fmt);
        print_zulu_time();
        printf(BG_YELLOW COLOR_RED COLOR_BOLD " CRITICAL " COLOR_RESET " ");
        print_lib_name();
        vprintf(fmt, args);
        va_end(args);
    }
}

void print_error(const char *fmt, ...) {
    if (log_level <= ERROR) {
        va_list args;
        va_start(args, fmt);
        print_zulu_time();
        printf(COLOR_RED "ERROR " COLOR_RESET);
        print_lib_name();
        vprintf(fmt, args);
        va_end(args);
    }
}

// check if the file descriptor corresponds to the I2C path we want to intercept
int is_redir_i2c(int fd) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char    resolved_path[256];
    ssize_t len = readlink(path, resolved_path, sizeof(resolved_path) - 1);
    if (len != -1) {
        resolved_path[len] = '\0';
        return strcmp(resolved_path, DUMMY_PATH) == 0;
    }
    return 0;
}

// Print the buffer in a hex format
// ex: [01 A2 04 FF]
void print_buffer(const unsigned char *buf, size_t len) {
    printf("[");
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
        if (i < len - 1) {
            printf(" ");
        }
    }
    printf("]");
}

// open the TTY device if not already opened
void open_tty() {
    if (tty_fd < 0) {
        static int (*real_open)(const char *, int, ...) = NULL;
        if (!real_open) {
            real_open = dlsym(RTLD_NEXT, "open");
            if (!real_open) {
                print_error("Error resolving original open: %s\n", dlerror());
                errno = ENOSYS;  // Function not implemented
                _exit(1);
            }
        }

        tty_fd = real_open(TTY_PATH, O_RDWR | O_NOCTTY);
        if (tty_fd < 0) {
            print_error("Failed to open TTY device %s: %s\n", TTY_PATH, strerror(errno));
            errno = EIO;  // Input/output error
            _exit(1);
        }
        struct termios tty;
        if (tcgetattr(tty_fd, &tty) != 0) {
            print_error("Error from tcgetattr: %s\n", strerror(errno));
            errno = EIO;  // Input/output error
            _exit(1);
        }
        cfsetospeed(&tty, B115200);                      // Set output speed to 115200 baud
        cfsetispeed(&tty, B115200);                      // Set input speed to 115200 baud
        tty.c_cflag &= ~PARENB;                          // Disable parity
        tty.c_cflag &= ~CSTOPB;                          // Use one stop bit (not two)
        tty.c_cflag &= ~CSIZE;                           // Clear the current character size setting
        tty.c_cflag |= CS8;                              // Set character size to 8 bits
        tty.c_cflag &= ~CRTSCTS;                         // Disable hardware flow control. Note: CRTSCTS is not defined on all systems, so we manually defined it in the header file.
        tty.c_cflag |= CREAD | CLOCAL;                   // Enable receiver, ignore modem control lines
        tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);  // Set raw input mode:
                                                         // ICANON: Disable canonical mode (read input byte-by-byte)
                                                         // ECHO: Disable input echo
                                                         // ECHOE: Disable erasure of input with backspace
                                                         // ISIG: Disable signal chars (e.g., Ctrl-C)
        tty.c_iflag &= ~(IXON | IXOFF | IXANY);          // Disable software flow control
        tty.c_oflag &= ~OPOST;                           // Disable output processing
        tty.c_cc[VMIN]  = 62;                            // Set minimum number of characters to read before returning
        tty.c_cc[VTIME] = 1;                             // Set timeout for read operations to 1 decisecond (100 ms)
        if (tcsetattr(tty_fd, TCSANOW, &tty) != 0) {
            print_error("Error from tcsetattr: %s\n", strerror(errno));
            errno = EIO;  // Input/output error
            _exit(1);
        }
        print_info("Opened TTY device %s\n", TTY_PATH);
    }
}
