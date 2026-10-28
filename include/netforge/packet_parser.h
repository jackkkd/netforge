#ifndef NETFORGE_PACKET_PARSER_H
#define NETFORGE_PACKET_PARSER_H
#include "job.h"
typedef struct { unsigned interval, limit, malformed; } NfPacketSettings;
bool nf_packet_parse(const unsigned char *packet, size_t captured, char *output, size_t capacity);
size_t nf_packet_build(unsigned char packet[60], uint32_t sequence);
bool nf_packets_parse_settings(const char *interval, const char *limit,
    const char *malformed, NfPacketSettings *out, char *error, size_t capacity);
bool nf_packets_start(NfJob *job, const NfPacketSettings *settings);
int nf_packet_self_test(void);
#endif
