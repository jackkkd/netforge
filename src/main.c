#include "netforge/ui.h"
#include "netforge/packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--self-test")) return nf_packet_self_test();
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        puts("NETFORGE 3.0 - modular C networking laboratory\n"
             "Usage: netforge [--no-splash | --self-test | --help]\n"
             "Standalone programs: netforge-scan, netforge-http, netforge-packets.");
        return EXIT_SUCCESS;
    }
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--no-splash"))) {
        fprintf(stderr, "Unknown option. Use --help for usage.\n"); return 2;
    }
    return nf_ui_run(argc == 2);
}
