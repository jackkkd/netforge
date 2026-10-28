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
static pthread_mutex_t logs_lock = PTHREAD_MUTEX_INITIALIZER;
static NfLogEntry logs[NF_LOG_CAPACITY];
static size_t log_head, log_count;
static bool console_output;
void nf_log_emit(int level, const char *source, const char *format, ...)
{
    static const char *marks[] = { "i", "+", "!", "x" };
    char message[200], stamp[16] = "--:--:--";
    struct tm local;
    time_t now = time(NULL);
    va_list args;
    if (now != (time_t)-1 && localtime_r(&now, &local))
        (void)strftime(stamp, sizeof stamp, "%H:%M:%S", &local);
    va_start(args, format);
    (void)vsnprintf(message, sizeof message, format, args);
    va_end(args);
    pthread_mutex_lock(&logs_lock);
    size_t index = (log_head + log_count) % NF_LOG_CAPACITY;
    if (log_count == NF_LOG_CAPACITY) log_head = (log_head + 1U) % NF_LOG_CAPACITY;
    else ++log_count;
    logs[index].level = level;
    (void)snprintf(logs[index].text, NF_LOG_LINE_SIZE, "[%s] [%s] [%s] %s",
                   stamp, source, marks[level], message);
    if (console_output) { fputs(logs[index].text, stdout); fputc('\n', stdout); fflush(stdout); }
    pthread_mutex_unlock(&logs_lock);
}


size_t nf_log_snapshot(NfLogEntry *destination, size_t capacity)
{
    if (!destination || !capacity) return 0;
    pthread_mutex_lock(&logs_lock);
    size_t count = log_count < capacity ? log_count : capacity;
    size_t first = log_count - count;
    for (size_t i = 0; i < count; ++i) destination[i] = logs[(log_head + first + i) % NF_LOG_CAPACITY];
    pthread_mutex_unlock(&logs_lock);
    return count;
}
void nf_log_clear(void)
{
    pthread_mutex_lock(&logs_lock); log_head = log_count = 0; pthread_mutex_unlock(&logs_lock);
}
void nf_log_set_console(bool enabled)
{
    pthread_mutex_lock(&logs_lock); console_output = enabled; pthread_mutex_unlock(&logs_lock);
}
