#include "netforge/job.h"
#include "netforge/log.h"
#include "netforge/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "net_io.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
int nf_make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1 || descriptor_flags == -1 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) == -1) return -1;
    return 0;
}

int nf_tcp_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd != -1 && nf_make_nonblocking(fd) == -1) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

/* 1=ready (including socket errors/hangup), 0=timeout, -1=error, -2=stop. */
int nf_wait_fd(int fd, short events, int64_t deadline, NfJob *job)
{
    struct pollfd item = { .fd = fd, .events = events };
    while (!atomic_load(&job->stop)) {
        int64_t now = nf_now_ms();
        if (now < 0) return -1;
        int64_t remaining = deadline - now;
        if (remaining <= 0) return 0;
        item.revents = 0;
        int result = poll(&item, 1, remaining > 100 ? 100 : (int)remaining);
        if (result == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (result > 0) {
            if (item.revents & POLLNVAL) { errno = EBADF; return -1; }
            return 1;
        }
    }
    return -2;
}
