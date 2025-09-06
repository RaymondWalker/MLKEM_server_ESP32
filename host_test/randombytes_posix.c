#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

void randombytes(uint8_t *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open(/dev/urandom)"); _exit(1); }
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) { perror("read(/dev/urandom)"); close(fd); _exit(1); }
        off += (size_t)r;
    }
    close(fd);
}
