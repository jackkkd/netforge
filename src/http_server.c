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
#include "netforge/http_server.h"
#include "net_io.h"
#include <sys/socket.h>
#include <poll.h>
#define HTTP_LIMIT 65536U
static const char default_html[] =
    "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>NETFORGE</title><style>body{background:#101820;color:#ecf2ff;"
    "font:18px monospace;max-width:760px;margin:12vh auto;padding:24px}"
    "h1{color:#64dfba}</style><h1>NETFORGE // SERVER ONLINE</h1>"
    "<p>200 OK. This page was served by a C11 program using POSIX sockets.</p>"
    "<p>TCP scanner &bull; HTTP server &bull; simulated packet parser</p>"
    "<p>Create index.html in the working directory to supply your own page, "
    "then restart the server.</p></html>\n";

static bool load_page(char **owned, const char **body, size_t *length)
{
    *owned = NULL;
    *body = default_html;
    *length = sizeof default_html - 1U;
    FILE *file = fopen("index.html", "rb");
    if (!file) {
        if (errno == ENOENT) {
            nf_log_emit(NF_INFO, "HTTP", "Using the built-in welcome page; index.html was not found.");
            return true;
        }
        nf_log_emit(NF_FAILURE, "HTTP", "Cannot open index.html: %s", strerror(errno));
        return false;
    }
    long size = -1;
    if (!fseek(file, 0, SEEK_END)) size = ftell(file);
    if (size < 0 || (unsigned long)size > HTTP_LIMIT || fseek(file, 0, SEEK_SET)) {
        nf_log_emit(NF_FAILURE, "HTTP", "index.html must be a readable file of at most 64 KiB.");
        fclose(file);
        return false;
    }
    char *buffer = malloc((size_t)size + 1U);
    if (!buffer) {
        nf_log_emit(NF_FAILURE, "HTTP", "Not enough memory to load index.html.");
        fclose(file);
        return false;
    }
    size_t read_count = fread(buffer, 1, (size_t)size, file);
    bool okay = read_count == (size_t)size && !ferror(file);
    if (fclose(file)) okay = false;
    if (!okay) {
        nf_log_emit(NF_FAILURE, "HTTP", "Could not read all of index.html.");
        free(buffer);
        return false;
    }
    buffer[read_count] = '\0';
    *owned = buffer;
    *body = buffer;
    *length = read_count;
    nf_log_emit(NF_INFO, "HTTP", "Loaded index.html (%zu bytes).", read_count);
    return true;
}

static bool send_bytes(int fd, const char *bytes, size_t length,
                       int64_t deadline, NfJob *job)
{
    size_t sent = 0;
    while (sent < length && !atomic_load(&job->stop)) {
        if (nf_wait_fd(fd, POLLOUT, deadline, job) != 1) return false;
        ssize_t count = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
        if (count > 0) sent += (size_t)count;
        else if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        else return false;
    }
    return sent == length;
}

static bool read_request(int fd, char *request, size_t capacity, NfJob *job)
{
    size_t used = 0;
    int64_t now = nf_now_ms();
    if (now < 0) return false;
    int64_t deadline = now + 1500;
    while (used + 1U < capacity) {
        if (nf_wait_fd(fd, POLLIN, deadline, job) != 1) return false;
        ssize_t count = recv(fd, request + used, capacity - used - 1U, 0);
        if (count > 0) {
            if (memchr(request + used, '\0', (size_t)count)) return false;
            used += (size_t)count;
            request[used] = '\0';
            if (strstr(request, "\r\n\r\n")) return true;
        } else if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        else return false;
    }
    return false;
}

/* Return true only when a 200 response was completely sent. */
static bool serve(int fd, const char *ip, const char *html, size_t html_length, NfJob *job)
{
    char request[4096], method[16], path[1024], version[16], extra;
    if (!read_request(fd, request, sizeof request, job)) {
        if (!atomic_load(&job->stop))
            nf_log_emit(NF_INFO, "HTTP", "%s disconnected or sent no complete request within 1.5s.", ip);
        return false;
    }
    char *line_end = strstr(request, "\r\n");
    if (line_end) *line_end = '\0';
    const char *response = "400 Bad Request", *body = "400 Bad Request\n";
    const char *additional = "";
    size_t length = strlen(body);
    bool head_only = false, okay = false;
    if (sscanf(request, "%15s %1023s %15s %c", method, path, version, &extra) == 3 &&
        (!strcmp(version, "HTTP/1.1") || !strcmp(version, "HTTP/1.0"))) {
        head_only = !strcmp(method, "HEAD");
        if (strcmp(method, "GET") && !head_only) {
            response = "405 Method Not Allowed";
            body = "405 Method Not Allowed\n";
            additional = "Allow: GET, HEAD\r\n";
        } else if (strcmp(path, "/") && strcmp(path, "/index.html")) {
            response = "404 Not Found";
            body = "404 Not Found\n";
        } else {
            response = "200 OK";
            body = html;
            okay = true;
        }
        length = okay ? html_length : strlen(body);
    }
    char header[512];
    int count = snprintf(header, sizeof header,
        "HTTP/1.1 %s\r\nServer: NETFORGE\r\nContent-Type: %s; charset=utf-8\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n%s\r\n",
        response, okay ? "text/html" : "text/plain", length, additional);
    int64_t now = nf_now_ms();
    bool sent = count > 0 && (size_t)count < sizeof header && now >= 0;
    if (sent) sent = send_bytes(fd, header, (size_t)count, now + 1500, job);
    if (sent && !head_only) sent = send_bytes(fd, body, length, now + 1500, job);
    if (!atomic_load(&job->stop))
        nf_log_emit(sent && okay ? NF_SUCCESS : NF_WARNING, "HTTP", "%s -> %s%s", ip,
             response, sent ? "" : " (response incomplete)");
    return sent && okay;
}

static void *http_worker(void *argument)
{
    NfJob *job = argument;
    NfHttpSettings settings = *(const NfHttpSettings *)job->config;
    NfMetrics metrics = nf_job_snapshot(job);
    bool failed = false;
    int listener = -1;
    char *owned = NULL;
    const char *body = NULL;
    size_t length = 0;
    if (!load_page(&owned, &body, &length)) { failed = true; goto cleanup; }
    listener = nf_tcp_socket();
    if (listener == -1) {
        nf_log_emit(NF_FAILURE, "HTTP", "Cannot create listener: %s", strerror(errno));
        failed = true;
        goto cleanup;
    }
    int reuse = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse) == -1) {
        nf_log_emit(NF_FAILURE, "HTTP", "Cannot configure listener: %s", strerror(errno));
        failed = true;
        goto cleanup;
    }
    struct sockaddr_in address = { .sin_family = AF_INET,
        .sin_port = htons((uint16_t)settings.port), .sin_addr = settings.address };
    if (bind(listener, (struct sockaddr *)&address, sizeof address) == -1) {
        int bind_error = errno;
        nf_log_emit(NF_FAILURE, "HTTP", "Cannot bind port %u: %s", settings.port, strerror(bind_error));
        if (bind_error == EADDRINUSE)
            nf_log_emit(NF_INFO, "HTTP", "Another process uses this port. Stop it or choose another port.");
        failed = true;
        goto cleanup;
    }
    if (listen(listener, 16) == -1) {
        nf_log_emit(NF_FAILURE, "HTTP", "Cannot listen: %s", strerror(errno));
        failed = true;
        goto cleanup;
    }
    atomic_store(&job->state, NF_RUNNING);
    char bind_ip[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &settings.address, bind_ip, sizeof bind_ip))
        (void)snprintf(bind_ip, sizeof bind_ip, "unknown");
    nf_log_emit(NF_SUCCESS, "HTTP", "Listening on %s:%u. Press Enter on this screen to stop.",
         bind_ip, settings.port);
    while (!atomic_load(&job->stop)) {
        int64_t now = nf_now_ms();
        int ready = now < 0 ? -1 : nf_wait_fd(listener, POLLIN, now + 250, job);
        if (ready == -2) break;
        if (!ready) continue;
        if (ready == -1) {
            nf_log_emit(NF_FAILURE, "HTTP", "Listener wait failed: %s", strerror(errno));
            failed = true;
            break;
        }
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof peer;
        int client = accept(listener, (struct sockaddr *)&peer, &peer_length);
        if (client == -1) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            nf_log_emit(NF_FAILURE, "HTTP", "Cannot accept client: %s", strerror(errno));
            failed = true;
            break;
        }
        ++metrics.checked;
        if (nf_make_nonblocking(client) == -1) {
            nf_log_emit(NF_WARNING, "HTTP", "Cannot configure client socket: %s", strerror(errno));
            ++metrics.bad;
        } else {
            char ip[INET_ADDRSTRLEN] = "unknown";
            (void)inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
            nf_log_emit(NF_INFO, "HTTP", "Client connected: %s:%u", ip, (unsigned)ntohs(peer.sin_port));
            nf_job_publish(job, &metrics);
            if (serve(client, ip, body, length, job)) ++metrics.good;
            else ++metrics.bad;
        }
        close(client);
        nf_job_publish(job, &metrics);
    }
cleanup:
    if (listener != -1) close(listener);
    free(owned);
    nf_log_emit(failed ? NF_FAILURE : NF_INFO, "HTTP", "Server %s. Clients: %u; completed 200 responses: %u.",
         failed ? "failed" : "stopped", metrics.checked, metrics.good);
    nf_job_finish(job, &metrics, failed);
    return NULL;
}


bool nf_http_parse_settings(const char *address, const char *port,
    NfHttpSettings *out, char *error, size_t capacity)
{
    NfHttpSettings settings;
    if (!out || inet_pton(AF_INET, address, &settings.address) != 1 ||
        !nf_parse_unsigned(port, 1024, 65535, &settings.port)) {
        snprintf(error, capacity, "Use a valid listen IPv4 address and port 1024-65535."); return false;
    }
    *out = settings; return true;
}
bool nf_http_start(NfJob *job, const NfHttpSettings *settings)
{
    if (!settings || settings->port < 1024 || settings->port > 65535) {
        nf_log_emit(NF_WARNING, "HTTP", "Choose a port between 1024 and 65535."); return false;
    }
    return nf_job_start(job, http_worker, settings, sizeof *settings, 0);
}
