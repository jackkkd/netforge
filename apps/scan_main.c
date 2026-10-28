#include "cli_common.h"
#include "netforge/scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void usage(void)
{
    puts("NETFORGE TCP scanner - scan only authorized systems.\n"
         "Usage: netforge-scan [FIRST_IP LAST_IP FIRST_PORT LAST_PORT [TIMEOUT_MS]] [--verbose]\n"
         "Default: 127.0.0.1 through 127.0.0.1, ports 8075-8085, timeout 250 ms.\n"
         "Example: netforge-scan 127.0.0.1 127.0.0.1 8075 8085 --verbose");
}
int main(int argc, char **argv)
{
    if (argc == 2 && nf_cli_help(argv[1])) { usage(); return 0; }
    bool verbose = argc > 1 && !strcmp(argv[argc - 1], "--verbose");
    if (verbose) --argc;
    if (argc != 1 && argc != 5 && argc != 6) { usage(); return 2; }
    NfScanSettings settings; char error[160];
    if (!nf_scanner_parse_settings(argc == 1 ? "127.0.0.1" : argv[1],
        argc == 1 ? "127.0.0.1" : argv[2], argc == 1 ? "8075" : argv[3],
        argc == 1 ? "8085" : argv[4], argc == 6 ? argv[5] : "250",
        verbose, &settings, error, sizeof error)) {
        fprintf(stderr, "netforge-scan: %s\n", error); return 2;
    }
    NfJob job;
    if (!nf_cli_initialize(&job, "SCAN")) return 1;
    if (!nf_scanner_start(&job, &settings)) { nf_job_destroy(&job); return 1; }
    return nf_cli_wait(&job);
}
