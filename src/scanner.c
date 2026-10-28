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
#include "netforge/scanner.h"
#include "net_io.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
enum { OPEN_PORT, CLOSED_PORT, NO_REPLY, UNREACHABLE, PROBE_ERROR, CANCELLED };
static int classify_connect(int error)
{
    if (!error) return OPEN_PORT;
    if (error == ECONNREFUSED) return CLOSED_PORT;
    if (error == ETIMEDOUT) return NO_REPLY;
    if (error == ENETUNREACH || error == EHOSTUNREACH || error == EACCES ||
        error == EPERM || error == ECONNRESET) return UNREACHABLE;
    errno = error;
    return PROBE_ERROR;
}

static int probe(uint32_t ip, unsigned port, unsigned timeout, NfJob *job)
{
    int fd = nf_tcp_socket();
    if (fd == -1) return PROBE_ERROR;
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
        .sin_addr = { .s_addr = htonl(ip) }
    };
    int result = connect(fd, (struct sockaddr *)&address, sizeof address);
    int answer;
    if (!result) answer = OPEN_PORT;
    else if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
        answer = classify_connect(errno);
    else {
        int64_t now = nf_now_ms();
        int ready = now < 0 ? -1 : nf_wait_fd(fd, POLLOUT, now + timeout, job);
        if (ready == 0) answer = NO_REPLY;
        else if (ready == -2) answer = CANCELLED;
        else if (ready == -1) answer = PROBE_ERROR;
        else {
            int error = 0;
            socklen_t length = sizeof error;
            answer = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == -1
                         ? PROBE_ERROR : classify_connect(error);
        }
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return answer;
}

static void *scan_worker(void *argument)
{
    NfJob *job = argument;
    NfScanSettings settings = *(const NfScanSettings *)job->config;
    NfMetrics metrics = nf_job_snapshot(job);
    bool failed = false;
    atomic_store(&job->state, NF_RUNNING);
    nf_log_emit(NF_INFO, "SCAN", "Starting scan: %u connection checks; wait up to %u ms per port.",
         metrics.total, settings.timeout);
    nf_log_emit(NF_INFO, "SCAN", "Each result identifies the target device, TCP port, state, and reason.");
    uint64_t hosts = (uint64_t)settings.last - settings.first + 1U;
    for (uint64_t host = 0; host < hosts && !failed; ++host) {
        uint32_t ip = settings.first + (uint32_t)host;
        struct in_addr address = { .s_addr = htonl(ip) };
        char text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &address, text, sizeof text)) {
            nf_log_emit(NF_FAILURE, "SCAN", "Cannot format target address: %s", strerror(errno));
            failed = true;
            break;
        }
        for (unsigned port = settings.first_port; port <= settings.last_port; ++port) {
            if (atomic_load(&job->stop)) break;
            int result = probe(ip, port, settings.timeout, job);
            if (result == CANCELLED) break;
            if (result == PROBE_ERROR) {
                nf_log_emit(NF_FAILURE, "SCAN", "Local socket error: %s", strerror(errno));
                failed = true;
                break;
            }
            ++metrics.checked;
            if (result == OPEN_PORT) ++metrics.good;
            else if (result == CLOSED_PORT) ++metrics.bad;
            else ++metrics.other;
            nf_job_publish(job, &metrics);
            if (result == OPEN_PORT || settings.verbose) {
                const char *state = result == OPEN_PORT ? "OPEN" :
                                    result == CLOSED_PORT ? "CLOSED" : "UNCERTAIN";
                const char *reason = result == OPEN_PORT ? "connection accepted" :
                    result == CLOSED_PORT ? "connection refused" :
                    result == NO_REPLY ? "no reply before timeout" : "unreachable/blocked";
                nf_log_emit(result == OPEN_PORT ? NF_SUCCESS : NF_INFO, "SCAN",
                     "Target IP: %s | TCP port: %u\nState: %s | Reason: %s", text, port, state, reason);
            }
        }
        if (atomic_load(&job->stop)) break;
    }
    int64_t end = nf_now_ms();
    double seconds = end >= metrics.started ? (end - metrics.started) / 1000.0 : 0;
    nf_log_emit(failed ? NF_FAILURE : NF_SUCCESS, "SCAN", "%s: %u/%u checked in %.2fs.",
         failed ? "Failed" : atomic_load(&job->stop) ? "Stopped" : "Finished",
         metrics.checked, metrics.total, seconds);
    nf_log_emit(NF_INFO, "SCAN", "Open: %u | Closed/refused: %u | Uncertain: %u.",
         metrics.good, metrics.bad, metrics.other);
    if (metrics.other) nf_log_emit(NF_WARNING, "SCAN", "No reply does not prove a firewall or a closed port.");
    nf_job_finish(job, &metrics, failed);
    return NULL;
}


static bool valid_scan(const NfScanSettings *s, unsigned *total, char *error, size_t capacity)
{
    const char *reason = NULL;
    if (!s || !s->first_port || s->last_port > 65535 || s->timeout < 50 || s->timeout > 3000)
        reason = "Ports must be 1-65535; timeout must be 50-3000 ms.";
    else if (s->first > s->last || s->first_port > s->last_port)
        reason = "The first address/port must not exceed the last.";
    else {
        uint64_t hosts = (uint64_t)s->last - s->first + 1U;
        uint64_t ports = (uint64_t)s->last_port - s->first_port + 1U;
        if (hosts > 256 || ports > 4096 || hosts * ports > 65536)
            reason = "Limit: 256 IPv4 addresses, 4096 ports, 65536 total probes.";
        else *total = (unsigned)(hosts * ports);
    }
    if (reason) { if (error && capacity) snprintf(error, capacity, "%s", reason); return false; }
    return true;
}
bool nf_scanner_parse_settings(const char *first_ip, const char *last_ip,
    const char *first_port, const char *last_port, const char *timeout,
    bool verbose, NfScanSettings *out, char *error, size_t capacity)
{
    struct in_addr first, last;
    NfScanSettings result = { .verbose = verbose };
    unsigned total;
    if (!out || inet_pton(AF_INET, first_ip, &first) != 1 || inet_pton(AF_INET, last_ip, &last) != 1) {
        snprintf(error, capacity, "Use complete IPv4 addresses, such as 127.0.0.1."); return false;
    }
    if (!nf_parse_unsigned(first_port, 1, 65535, &result.first_port) ||
        !nf_parse_unsigned(last_port, 1, 65535, &result.last_port) || !nf_parse_unsigned(timeout, 50, 3000, &result.timeout)) {
        snprintf(error, capacity, "Ports: 1-65535. Timeout: 50-3000 ms."); return false;
    }
    result.first = ntohl(first.s_addr); result.last = ntohl(last.s_addr);
    if (!valid_scan(&result, &total, error, capacity)) return false;
    *out = result;
    return true;
}
bool nf_scanner_start(NfJob *job, const NfScanSettings *settings)
{
    char error[160]; unsigned total;
    if (!valid_scan(settings, &total, error, sizeof error)) {
        nf_log_emit(NF_WARNING, "SCAN", "%s", error); return false;
    }
    return nf_job_start(job, scan_worker, settings, sizeof *settings, total);
}
