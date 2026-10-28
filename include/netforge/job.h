#ifndef NETFORGE_JOB_H
#define NETFORGE_JOB_H
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
enum { NF_IDLE, NF_STARTING, NF_RUNNING, NF_FINISHED, NF_STOPPED, NF_FAILED };
typedef struct { unsigned checked, good, bad, other, total; int64_t started, ended; } NfMetrics;
/* live/config are owned by the controlling thread. Workers read their config copy. */
typedef struct {
    const char *name;
    pthread_t thread;
    bool live;
    atomic_bool stop, done;
    atomic_int state;
    pthread_mutex_t lock;
    NfMetrics metrics;
    void *config;
} NfJob;
/* Initialize once; the controller starts, stops, joins, then destroys the job. */
bool nf_job_init(NfJob *job, const char *name);
/* Settings are copied before the worker starts and freed after it is joined. */
bool nf_job_start(NfJob *job, void *(*worker)(void *), const void *config,
                  size_t config_size, unsigned total);
void nf_job_stop(NfJob *job);
bool nf_job_reap(NfJob *job);
bool nf_job_join(NfJob *job);
bool nf_job_destroy(NfJob *job);
NfMetrics nf_job_snapshot(NfJob *job);
void nf_job_publish(NfJob *job, const NfMetrics *metrics);
void nf_job_finish(NfJob *job, NfMetrics *metrics, bool failed);
const char *nf_job_status(NfJob *job);
#endif
