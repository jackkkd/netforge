#ifndef NETFORGE_CLI_COMMON_H
#define NETFORGE_CLI_COMMON_H
#include "netforge/job.h"
bool nf_cli_initialize(NfJob *job, const char *name);
int nf_cli_wait(NfJob *job);
bool nf_cli_help(const char *argument);
#endif
