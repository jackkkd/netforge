#ifndef NETFORGE_HTTP_SERVER_H
#define NETFORGE_HTTP_SERVER_H
#include "job.h"
#include <arpa/inet.h>
typedef struct { struct in_addr address; unsigned port; } NfHttpSettings;
bool nf_http_parse_settings(const char *address, const char *port,
    NfHttpSettings *out, char *error, size_t capacity);
bool nf_http_start(NfJob *job, const NfHttpSettings *settings);
#endif
