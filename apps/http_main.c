#include "cli_common.h"
#include "netforge/http_server.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    if (argc > 3 || (argc == 2 && nf_cli_help(argv[1]))) {
        puts("Usage: netforge-http [LISTEN_IPV4 [PORT]]\n"
             "Default: 127.0.0.1:8080. Use 0.0.0.0 to listen on all IPv4 interfaces.\n"
             "Serves ./index.html or a built-in page. Ctrl-C stops the server.");
        return argc > 3 ? 2 : 0;
    }
    NfHttpSettings settings; char error[160];
    if (!nf_http_parse_settings(argc > 1 ? argv[1] : "127.0.0.1",
        argc > 2 ? argv[2] : "8080", &settings, error, sizeof error)) {
        fprintf(stderr, "netforge-http: %s\n", error); return 2;
    }
    NfJob job;
    if (!nf_cli_initialize(&job, "HTTP")) return 1;
    if (!nf_http_start(&job, &settings)) { nf_job_destroy(&job); return 1; }
    return nf_cli_wait(&job);
}
