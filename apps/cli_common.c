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
#include "cli_common.h"
#include <signal.h>
static volatile sig_atomic_t stop_signal;
static void catch_signal(int value) { stop_signal = value; }
bool nf_cli_help(const char *argument) { return !strcmp(argument, "--help") || !strcmp(argument, "-h"); }
bool nf_cli_initialize(NfJob *job, const char *name)
{
    nf_log_set_console(true);
    struct sigaction action;
    memset(&action, 0, sizeof action); action.sa_handler = catch_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
        perror("Cannot configure shutdown signals"); return false;
    }
    return nf_job_init(job, name);
}
int nf_cli_wait(NfJob *job)
{
    while (!atomic_load(&job->done)) {
        if (stop_signal) nf_job_stop(job);
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 50000000L };
        if (nanosleep(&delay, NULL) == -1 && errno != EINTR) nf_job_stop(job);
    }
    if (!nf_job_join(job)) return EXIT_FAILURE;
    bool failed = atomic_load(&job->state) == NF_FAILED;
    if (!nf_job_destroy(job)) return EXIT_FAILURE;
    return stop_signal ? 128 + stop_signal : failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
