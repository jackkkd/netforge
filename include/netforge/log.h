#ifndef NETFORGE_LOG_H
#define NETFORGE_LOG_H
#include <stdbool.h>
#include <stddef.h>
#define NF_LOG_CAPACITY 512
#define NF_LOG_LINE_SIZE 256
enum { NF_INFO, NF_SUCCESS, NF_WARNING, NF_FAILURE };
typedef struct { int level; char text[NF_LOG_LINE_SIZE]; } NfLogEntry;
void nf_log_emit(int level, const char *source, const char *format, ...);
size_t nf_log_snapshot(NfLogEntry *destination, size_t capacity);
void nf_log_clear(void);
void nf_log_set_console(bool enabled);
#endif
