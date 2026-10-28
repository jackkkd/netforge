/* Integration checks use public APIs and loopback connections only. */
#include "netforge/job.h"
#include "netforge/log.h"
#include "netforge/scanner.h"
#include "netforge/http_server.h"
#include "netforge/packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
static int checks, failures;
static void check(bool okay, const char *description)
{
    ++checks;
    printf("%s %s\n", okay ? "PASS" : "FAIL", description);
    if (!okay) ++failures;
}
static void pause_ms(unsigned ms)
{
    struct timespec delay = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000 };
    while (nanosleep(&delay, &delay) == -1 && errno == EINTR) {}
}
static bool completed(NfJob *job)
{
    for (int i = 0; i < 1000 && !atomic_load(&job->done); ++i) pause_ms(10);
    if (!atomic_load(&job->done)) { nf_job_stop(job); return false; }
    (void)nf_job_reap(job);
    return !job->live;
}
static int reserve_port(unsigned *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr = { htonl(INADDR_LOOPBACK) } };
    socklen_t length = sizeof address;
    if (fd == -1 || bind(fd, (struct sockaddr *)&address, length) ||
        getsockname(fd, (struct sockaddr *)&address, &length)) {
        if (fd != -1) close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return fd;
}
static bool request(unsigned port, const char *method, const char *path, const char *expected, bool head)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout_value = { .tv_sec = 3 };
    if (fd == -1) return false;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout_value, sizeof timeout_value);
    struct sockaddr_in address = { .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port), .sin_addr = { htonl(INADDR_LOOPBACK) } };
    if (connect(fd, (struct sockaddr *)&address, sizeof address)) { close(fd); return false; }
    char buffer[8192], query[256];
    int n = snprintf(query, sizeof query, "%s %s HTTP/1.1\r\nHost: localhost\r\n\r\n", method, path);
    if (send(fd, query, (size_t)n, MSG_NOSIGNAL) != n) { close(fd); return false; }
    size_t used = 0;
    ssize_t count;
    while (used + 1 < sizeof buffer && (count = recv(fd, buffer + used, sizeof buffer - used - 1, 0)) > 0)
        used += (size_t)count;
    close(fd);
    buffer[used] = 0;
    char *split = strstr(buffer, "\r\n\r\n");
    return strstr(buffer, expected) && split && (!head || split[4] == 0);
}
static bool read_until(int fd, char *buffer, size_t capacity, size_t *used, const char *token)
{
    for (int i = 0; i < 200; ++i) {
        if (strstr(buffer, token)) return true;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, 10) > 0 && (p.revents & POLLIN)) {
            ssize_t count = read(fd, buffer + *used, capacity - *used - 1);
            if (count <= 0) break;
            *used += (size_t)count; buffer[*used] = 0;
            if (*used + 1 == capacity) break;
        }
    }
    return strstr(buffer, token) != NULL;
}

static pid_t spawn_cli(char *const arguments[])
{
    pid_t child = fork();
    if (child == 0) {
        int sink = open("/dev/null", O_WRONLY);
        if (sink != -1) { dup2(sink, STDOUT_FILENO); dup2(sink, STDERR_FILENO); close(sink); }
        execv(arguments[0], arguments); _exit(127);
    }
    return child;
}
static int run_cli(char *const arguments[])
{
    pid_t child = spawn_cli(arguments);
    if (child < 0) return -1;
    int exit_status;
    if (waitpid(child, &exit_status, 0) != child || !WIFEXITED(exit_status)) return -1;
    return WEXITSTATUS(exit_status);
}

/* Exercise real ncurses output at different terminal sizes, not copied art. */
static bool splash_session(const char *program, unsigned height, unsigned width,
                           bool resize_test)
{
    struct winsize dimensions = { .ws_row = (unsigned short)height,
                                  .ws_col = (unsigned short)width };
    int master;
    pid_t child = forkpty(&master, NULL, NULL, &dimensions);
    if (child == 0) { execl(program, program, (char *)NULL); _exit(127); }
    if (child < 0) return false;
    char *output = calloc(262144, 1);
    if (!output) { kill(child, SIGTERM); waitpid(child, NULL, 0); close(master); return false; }
    size_t used = 0;
    bool okay = read_until(master, output, 262144, &used, "Enter: open main menu");
    char capture_name[128];
    snprintf(capture_name, sizeof capture_name, "build/splash-%ux%u.bin", width, height);
    FILE *capture = fopen(capture_name, "wb");
    if (capture) { fwrite(output, 1, used, capture); fclose(capture); }
    okay = okay && strstr(output, "N E T F O R G E");
    write(master, "\n", 1);
    okay = read_until(master, output, 262144, &used, "MAIN MENU") && okay;
    if (resize_test) {
        dimensions.ws_row = 16; dimensions.ws_col = 40;
        if (ioctl(master, TIOCSWINSZ, &dimensions) == -1) okay = false;
        okay = read_until(master, output, 262144, &used, "Please resize to 80x28") && okay;
    }
    write(master, "q", 1);
    int exit_status = 0;
    bool exited = false;
    for (int i = 0; i < 200; ++i) {
        if (waitpid(child, &exit_status, WNOHANG) == child) { exited = true; break; }
        pause_ms(10);
    }
    if (!exited) { kill(child, SIGTERM); waitpid(child, &exit_status, 0); }
    close(master); free(output);
    return okay && exited && WIFEXITED(exit_status) && !WEXITSTATUS(exit_status);
}
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char tui[1024], scanner[1024], server[1024], packets[1024];
    snprintf(tui, sizeof tui, "%s/netforge", argv[1]);
    snprintf(scanner, sizeof scanner, "%s/netforge-scan", argv[1]);
    snprintf(server, sizeof server, "%s/netforge-http", argv[1]);
    snprintf(packets, sizeof packets, "%s/netforge-packets", argv[1]);
    NfJob scan_job, http_job, packet_job;
    NfScanSettings scan_settings;
    NfHttpSettings http_settings;
    NfPacketSettings packet_settings;
    char error[160];
    check(!nf_scanner_parse_settings("127.0.0.2", "127.0.0.1", "1", "5", "100", false,
          &scan_settings, error, sizeof error), "Reversed address ranges are rejected");
    check(!nf_scanner_parse_settings("127.0.0.1", "127.0.0.1", "1", "65535", "100", false,
          &scan_settings, error, sizeof error), "Oversized scans are rejected");
    check(!nf_http_parse_settings("127.0.0.1", "80", &http_settings, error, sizeof error),
          "Listener settings enforce unprivileged port range");
    check(!nf_packets_parse_settings("0", "10", "8", &packet_settings, error, sizeof error),
          "Invalid simulation interval is rejected");
    NfJob *jobs[] = { &scan_job, &http_job, &packet_job };
    const char *names[] = { "SCAN", "HTTP", "SIM" };
    for (int i = 0; i < 3; ++i) if (!nf_job_init(jobs[i], names[i])) return 2;
    unsigned port = 0;
    int reserved = reserve_port(&port);
    if (reserved == -1) return 2;
    close(reserved);
    http_settings.address.s_addr = htonl(INADDR_LOOPBACK);
    http_settings.port = port;
    check(nf_http_start(&http_job, &http_settings), "HTTP worker starts");
    for (int i = 0; i < 300 && atomic_load(&http_job.state) == NF_STARTING; ++i) pause_ms(10);
    check(atomic_load(&http_job.state) == NF_RUNNING, "HTTP listener becomes ready");
    check(request(port, "GET", "/", "200 OK", false), "HTTP GET serves embedded HTML");
    check(request(port, "HEAD", "/", "200 OK", true), "HTTP HEAD sends headers without a body");
    check(request(port, "GET", "/missing", "404 Not Found", false), "HTTP unknown path returns 404");
    check(request(port, "POST", "/", "405 Method Not Allowed", false), "HTTP unsupported method returns 405");
    scan_settings = (NfScanSettings){ .first = 0x7f000001, .last = 0x7f000001,
        .first_port = port, .last_port = port, .timeout = 100, .verbose = true };
    check(nf_scanner_start(&scan_job, &scan_settings) && completed(&scan_job), "Scanner completes while HTTP runs");
    NfMetrics metrics = nf_job_snapshot(&scan_job);
    check(metrics.checked == 1 && metrics.good == 1, "Scanner recognizes an open TCP port");
    unsigned closed_port = 0;
    reserved = reserve_port(&closed_port);
    scan_settings.first_port = scan_settings.last_port = closed_port;
    check(reserved != -1 && nf_scanner_start(&scan_job, &scan_settings) && completed(&scan_job), "Closed-port scan completes");
    metrics = nf_job_snapshot(&scan_job);
    check(metrics.checked == 1 && metrics.bad == 1 && !metrics.other, "Refused connections are counted separately");
    if (reserved != -1) close(reserved);
    NfJob conflict;
    if (!nf_job_init(&conflict, "CONFLICT")) return 2;
    check(nf_http_start(&conflict, &http_settings) && completed(&conflict) &&
          atomic_load(&conflict.state) == NF_FAILED, "Occupied listen port reports failure cleanly");
    packet_settings = (NfPacketSettings){ .interval = 100, .limit = 9, .malformed = 3 };
    check(nf_packets_start(&packet_job, &packet_settings) && completed(&packet_job), "Finite packet simulation stops automatically");
    metrics = nf_job_snapshot(&packet_job);
    check(metrics.checked == 9 && metrics.good == 6 && metrics.bad == 3, "Valid and malformed packet counts are correct");
    nf_job_stop(&http_job);
    check(completed(&http_job) && atomic_load(&http_job.state) == NF_STOPPED, "HTTP cancellation joins the worker");
    scan_settings.first_port = 1; scan_settings.last_port = 4096;
    check(nf_scanner_start(&scan_job, &scan_settings), "Scanner can be started again");
    nf_job_stop(&scan_job);
    check(completed(&scan_job) && atomic_load(&scan_job.state) == NF_STOPPED, "Scan cancellation joins the worker");

    char port_text[16]; snprintf(port_text, sizeof port_text, "%u", port);
    char *scan_args[] = { scanner, "127.0.0.1", "127.0.0.1", port_text, port_text, "100", "--verbose", NULL };
    check(run_cli(scan_args) == 0, "Standalone scanner runs without a terminal");
    char *packet_args[] = { packets, "3", "100", "0", NULL };
    check(run_cli(packet_args) == 0, "Standalone simulation runs without a terminal");
    char *invalid_args[] = { packets, "3", "0", NULL };
    check(run_cli(invalid_args) == 2, "Standalone invalid input uses an error exit code");
    unsigned cli_port = 0;
    reserved = reserve_port(&cli_port);
    if (reserved == -1) return 2;
    close(reserved);
    snprintf(port_text, sizeof port_text, "%u", cli_port);
    char *http_args[] = { server, "127.0.0.1", port_text, NULL };
    pid_t http_child = spawn_cli(http_args);
    bool http_ready = false;
    if (http_child > 0) {
        for (int i = 0; i < 100 && !http_ready; ++i) {
            http_ready = request(cli_port, "GET", "/", "200 OK", false);
            if (!http_ready) pause_ms(10);
        }
        kill(http_child, SIGTERM);
        int exit_status;
        waitpid(http_child, &exit_status, 0);
        check(http_ready && WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 143,
              "Standalone HTTP serves requests and shuts down on SIGTERM");
    } else check(false, "Standalone HTTP process starts");
    for (int i = 0; i < 3; ++i) check(nf_job_destroy(jobs[i]), "Worker resources are released");
    check(nf_job_destroy(&conflict), "Failed worker resources are released");
    struct winsize size = { .ws_row = 28, .ws_col = 80 };
    int master;
    pid_t child = forkpty(&master, NULL, NULL, &size);
    if (child == 0) { execl(tui, tui, "--no-splash", (char *)NULL); _exit(127); }
    if (child < 0) return 2;
    static char terminal[262144];
    size_t used = 0;
    check(read_until(master, terminal, sizeof terminal, &used, "MAIN MENU"), "80x28 terminal shows the main menu");
    check(read_until(master, terminal, sizeof terminal, &used,
                     "Scanner: Ready | HTTP: Ready | Packets: Ready"),
          "Opening the app leaves every tool idle");
    write(master, "3", 1);
    check(read_until(master, terminal, sizeof terminal, &used, "SIMULATED packets:"), "Menu opens the selected tool without running it");
    write(master, "b4", 2);
    check(read_until(master, terminal, sizeof terminal, &used, "QUICK DEMONSTRATION"), "Back and Help navigation work");
    write(master, "q", 1);
    int child_status = 0;
    bool exited = false;
    for (int i = 0; i < 200; ++i) {
        if (waitpid(child, &child_status, WNOHANG) == child) { exited = true; break; }
        pause_ms(10);
    }
    if (!exited) { kill(child, SIGTERM); waitpid(child, &child_status, 0); }
    close(master);
    check(exited && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0, "Terminal exits cleanly with Q");
    FILE *capture = fopen("build/terminal-capture.bin", "wb");
    if (capture) { fwrite(terminal, 1, used, capture); fclose(capture); }
    check(splash_session(tui, 28, 80, false), "Small splash opens the menu at 80x28");
    check(splash_session(tui, 42, 90, false), "Medium splash and responsive header work at 90x42");
    check(splash_session(tui, 56, 104, false), "Detailed splash and large header work at 104x56");
    check(splash_session(tui, 36, 80, true), "Resizing to a small terminal stays responsive and Q exits");
    printf("Integration checks: %d/%d passed.\n", checks - failures, checks);
    return failures ? 1 : 0;
}
