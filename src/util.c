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
int64_t nf_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool nf_parse_unsigned(const char *text, unsigned minimum, unsigned maximum, unsigned *value)
{
    if (!*text) return false;
    for (const char *p = text; *p; ++p) if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || *end || parsed < minimum || parsed > maximum) return false;
    *value = (unsigned)parsed;
    return true;
}
