#ifndef NETFORGE_SCANNER_H
#define NETFORGE_SCANNER_H
#include "job.h"
/* IPv4 addresses are stored in host byte order. */
typedef struct {
    uint32_t first, last;
    unsigned first_port, last_port, timeout;
    bool verbose;
} NfScanSettings;
bool nf_scanner_parse_settings(const char *first_ip, const char *last_ip,
    const char *first_port, const char *last_port, const char *timeout,
    bool verbose, NfScanSettings *out, char *error, size_t capacity);
bool nf_scanner_start(NfJob *job, const NfScanSettings *settings);
#endif
