#ifndef NETFORGE_NET_IO_H
#define NETFORGE_NET_IO_H
#include "netforge/job.h"
int nf_make_nonblocking(int fd);
int nf_tcp_socket(void);
/* 1=event, 0=deadline, -1=error, -2=cancellation. */
int nf_wait_fd(int fd, short events, int64_t deadline, NfJob *job);
#endif
