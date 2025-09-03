#ifndef I2C_INTERCEPT_UTIL_H
#define I2C_INTERCEPT_UTIL_H

#include <stdint.h>
#include <sys/types.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>

#define COLOR_RESET "\033[0m"
#define COLOR_PURPLE "\033[35m"
#define COLOR_BLUE "\033[34m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED "\033[31m"
#define COLOR_GRAY "\033[90m"
#define COLOR_CYAN "\033[36m"
#define BG_YELLOW "\033[43m"
#define COLOR_FLASH "\033[5m"
#define COLOR_REVERSE "\033[7m"
#define COLOR_BOLD "\033[1m"
#define COLOR_WHITE "\033[37m"
#define COLOR_BLACK "\033[30m"

#ifndef FD_SETSIZE
#define FD_SETSIZE 1024  // this is the maximum number of file descriptors on most systems
#endif

#ifndef CRTSCTS  // if not defined, define it ourselves for maximum compatibility
#define CRTSCTS 020000000000
#endif

extern const char     *DUMMY_PATH;
extern const char     *I2C_PATH;
extern const char     *TTY_PATH;
extern int             tty_fd;
extern uint8_t         fd_i2c_addr[FD_SETSIZE];
extern pthread_mutex_t tty_mutex;

typedef enum {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
} LogLevel;
extern LogLevel log_level;

void print_zulu_time(void);
void print_lib_name(void);

void print_buffer(const unsigned char *buf, size_t len);

void print_trace(const char *fmt, ...);
void print_debug(const char *fmt, ...);
void print_info(const char *fmt, ...);
void print_warning(const char *fmt, ...);
void print_critical(const char *fmt, ...);
void print_error(const char *fmt, ...);

int  is_redir_i2c(int fd);
void open_tty();

#endif  // I2C_INTERCEPT_UTIL_H
