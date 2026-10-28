#include "cli_common.h"
#include "netforge/packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--self-test")) return nf_packet_self_test();
    if (argc > 4 || (argc == 2 && nf_cli_help(argv[1]))) {
        puts("Usage: netforge-packets [COUNT [INTERVAL_MS [MALFORMED_EVERY]]]\n"
             "Default: 10 simulated packets, 500 ms interval, every eighth sample malformed.\n"
             "COUNT=0 runs until Ctrl-C. MALFORMED_EVERY=0 disables malformed samples.\n"
             "Simulation only: no live capture and no traffic is transmitted.\n"
             "Use --self-test for parser regression checks.");
        return argc > 4 ? 2 : 0;
    }
    NfPacketSettings settings; char error[160];
    if (!nf_packets_parse_settings(argc > 2 ? argv[2] : "500", argc > 1 ? argv[1] : "10",
        argc > 3 ? argv[3] : "8", &settings, error, sizeof error)) {
        fprintf(stderr, "netforge-packets: %s\n", error); return 2;
    }
    NfJob job;
    if (!nf_cli_initialize(&job, "SIM")) return 1;
    if (!nf_packets_start(&job, &settings)) { nf_job_destroy(&job); return 1; }
    return nf_cli_wait(&job);
}
