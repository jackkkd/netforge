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
#include "netforge/packet_parser.h"
#include <arpa/inet.h>
static uint16_t be16(const unsigned char *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

static void put16(unsigned char *p, uint16_t value)
{ p[0] = (unsigned char)(value >> 8); p[1] = (unsigned char)value; }

static uint16_t checksum(const unsigned char *bytes, size_t length)
{
    uint32_t sum = 0;
    while (length >= 2U) { sum += be16(bytes); bytes += 2; length -= 2U; }
    if (length) sum += (uint32_t)bytes[0] << 8;
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

static bool reject_packet(char *output, size_t capacity, const char *reason)
{ (void)snprintf(output, capacity, "Rejected packet | Reason: %s", reason); return false; }

/* Input starts at IPv4, not Ethernet. TCP/UDP checksums are not validated. */
bool nf_packet_parse(const unsigned char *packet, size_t captured,
                         char *output, size_t capacity)
{
    if (!packet || captured < 20) return reject_packet(output, capacity, "truncated IPv4 header");
    if ((packet[0] >> 4) != 4) return reject_packet(output, capacity, "packet is not IPv4");
    size_t ihl = (size_t)(packet[0] & 15U) * 4U, total = be16(packet + 2);
    if (ihl < 20 || ihl > captured) return reject_packet(output, capacity, "invalid IPv4 header length");
    if (total < ihl || total > captured) return reject_packet(output, capacity, "invalid/truncated IPv4 size");
    if (checksum(packet, ihl)) return reject_packet(output, capacity, "IPv4 checksum mismatch");
    if (be16(packet + 6) & 0x3fffU) return reject_packet(output, capacity, "fragment requires reassembly");
    const unsigned char *transport = packet + ihl;
    size_t available = total - ihl;
    const char *protocol;
    if (packet[9] == IPPROTO_TCP) {
        if (available < 20) return reject_packet(output, capacity, "truncated TCP header");
        size_t size = (size_t)(transport[12] >> 4) * 4U;
        if (size < 20 || size > available) return reject_packet(output, capacity, "invalid TCP data offset");
        protocol = "TCP";
    } else if (packet[9] == IPPROTO_UDP) {
        if (available < 8) return reject_packet(output, capacity, "truncated UDP header");
        size_t size = be16(transport + 4);
        if (size < 8 || size > available) return reject_packet(output, capacity, "invalid UDP length");
        protocol = "UDP";
    } else return reject_packet(output, capacity, "unsupported transport protocol");
    char source[INET_ADDRSTRLEN], destination[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, packet + 12, source, sizeof source) ||
        !inet_ntop(AF_INET, packet + 16, destination, sizeof destination))
        return reject_packet(output, capacity, "cannot format IPv4 address");
    (void)snprintf(output, capacity,
         "Protocol: %s | Source IP: %s | Source port: %u\n"
         "Destination IP: %s | Destination port: %u | IP bytes: %zu",
         protocol, source, (unsigned)be16(transport), destination,
         (unsigned)be16(transport + 2), total);
    return true;
}

/* Header examples only: documentation IPs, no payload, never transmitted. */
size_t nf_packet_build(unsigned char packet[60], uint32_t sequence)
{
    bool tcp = sequence % 2U == 0;
    size_t length = tcp ? 40U : 28U;
    memset(packet, 0, 60);
    packet[0] = 0x45;
    put16(packet + 2, (uint16_t)length);
    put16(packet + 4, (uint16_t)sequence);
    put16(packet + 6, 0x4000);
    packet[8] = 64;
    packet[9] = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    packet[12] = 192; packet[14] = 2;
    packet[15] = (unsigned char)(sequence % 200U + 1U);
    packet[16] = 198; packet[17] = 51; packet[18] = 100; packet[19] = 20;
    put16(packet + 20, (uint16_t)(40000U + sequence % 20000U));
    put16(packet + 22, tcp ? 443 : 53);
    if (tcp) { packet[32] = 0x50; packet[33] = 2; put16(packet + 34, 64240); }
    else put16(packet + 24, 8);
    put16(packet + 10, checksum(packet, 20));
    return length;
}

static void *packet_worker(void *argument)
{
    NfJob *job = argument;
    NfPacketSettings settings = *(const NfPacketSettings *)job->config;
    NfMetrics metrics = nf_job_snapshot(job);
    uint32_t sequence = 0;
    bool failed = false;
    atomic_store(&job->state, NF_RUNNING);
    nf_log_emit(NF_INFO, "SIM", "Simulation started. These are generated examples, not captured traffic.");
    while (!atomic_load(&job->stop) && (!settings.limit || metrics.checked < settings.limit)) {
        unsigned char packet[60];
        char output[200];
        size_t size = nf_packet_build(packet, ++sequence);
        if (settings.malformed && sequence % settings.malformed == 0) size = 19;
        bool valid = nf_packet_parse(packet, size, output, sizeof output);
        ++metrics.checked;
        if (valid) ++metrics.good; else ++metrics.bad;
        nf_job_publish(job, &metrics);
        nf_log_emit(valid ? NF_SUCCESS : NF_WARNING, "SIM", "%s", output);
        if (settings.limit && metrics.checked >= settings.limit) break;
        unsigned remaining = settings.interval;
        while (remaining && !atomic_load(&job->stop)) {
            unsigned slice = remaining > 50 ? 50 : remaining;
            struct timespec delay = { .tv_sec = 0, .tv_nsec = (long)slice * 1000000L };
            int result;
            do { result = nanosleep(&delay, &delay); }
            while (result == -1 && errno == EINTR && !atomic_load(&job->stop));
            if (result == -1 && errno != EINTR) {
                nf_log_emit(NF_FAILURE, "SIM", "Cannot pause simulation: %s", strerror(errno));
                failed = true;
                break;
            }
            remaining -= slice;
        }
        if (failed) break;
    }
    nf_log_emit(failed ? NF_FAILURE : NF_INFO, "SIM", "%s. Samples: %u | decoded: %u | rejected: %u.",
         failed ? "Failed" : atomic_load(&job->stop) ? "Stopped" : "Finished",
         metrics.checked, metrics.good, metrics.bad);
    nf_job_finish(job, &metrics, failed);
    return NULL;
}


bool nf_packets_parse_settings(const char *interval, const char *limit,
    const char *malformed, NfPacketSettings *out, char *error, size_t capacity)
{
    NfPacketSettings settings;
    if (!out || !nf_parse_unsigned(interval, 100, 5000, &settings.interval) ||
        !nf_parse_unsigned(limit, 0, 100000, &settings.limit) || !nf_parse_unsigned(malformed, 0, 1000, &settings.malformed)) {
        snprintf(error, capacity, "Interval: 100-5000 ms; count: 0-100000; malformed N: 0-1000."); return false;
    }
    *out = settings; return true;
}
bool nf_packets_start(NfJob *job, const NfPacketSettings *settings)
{
    if (!settings || settings->interval < 100 || settings->interval > 5000 ||
        settings->limit > 100000 || settings->malformed > 1000) {
        nf_log_emit(NF_WARNING, "SIM", "Invalid simulation interval, count, or malformed frequency."); return false;
    }
    return nf_job_start(job, packet_worker, settings, sizeof *settings, settings->limit);
}
int nf_packet_self_test(void)
{
    unsigned char packet[60];
    char output[200];
    int passed = 0, total = 0;
#define CHECK(test) do { ++total; if (test) ++passed; else \
    fprintf(stderr, "FAIL at line %d: %s\n", __LINE__, #test); } while (0)
    size_t size = nf_packet_build(packet, 2);
    CHECK(nf_packet_parse(packet, size, output, sizeof output));
    CHECK(strstr(output, "Protocol: TCP") && strstr(output, "Destination port: 443"));
    CHECK(strstr(output, "Source IP: 192.0.2.3") && strstr(output, "Source port: 40002"));
    CHECK(strstr(output, "Destination IP: 198.51.100.20") && strstr(output, "IP bytes: 40"));
    size = nf_packet_build(packet, 1);
    CHECK(nf_packet_parse(packet, size, output, sizeof output));
    CHECK(strstr(output, "Protocol: UDP") && strstr(output, "Destination port: 53"));
    CHECK(strchr(output, '\n') != NULL);
    for (size_t i = 0; i < size; ++i) CHECK(!nf_packet_parse(packet, i, output, sizeof output));
    CHECK(!nf_packet_parse(NULL, 0, output, sizeof output));
    packet[8] ^= 1;
    CHECK(!nf_packet_parse(packet, size, output, sizeof output));
    size = nf_packet_build(packet, 2); packet[32] = 0x10;
    CHECK(!nf_packet_parse(packet, size, output, sizeof output));
    size = nf_packet_build(packet, 1); put16(packet + 24, 7);
    CHECK(!nf_packet_parse(packet, size, output, sizeof output));
    size = nf_packet_build(packet, 2); put16(packet + 6, 0x2000);
    put16(packet + 10, 0); put16(packet + 10, checksum(packet, 20));
    CHECK(!nf_packet_parse(packet, size, output, sizeof output));
    unsigned value;
    CHECK(nf_parse_unsigned("65535", 1, 65535, &value) && value == 65535);
    CHECK(!nf_parse_unsigned("65536", 1, 65535, &value));
    CHECK(!nf_parse_unsigned("-1", 1, 65535, &value));
    CHECK(!nf_parse_unsigned("", 1, 65535, &value));
    printf("NETFORGE self-test: %d/%d checks passed.\n", passed, total);
#undef CHECK
    return passed == total ? EXIT_SUCCESS : EXIT_FAILURE;
}
