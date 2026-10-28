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
NfMetrics nf_job_snapshot(NfJob *job)
{
    pthread_mutex_lock(&job->lock);
    NfMetrics result = job->metrics;
    pthread_mutex_unlock(&job->lock);
    return result;
}

void nf_job_publish(NfJob *job, const NfMetrics *metrics)
{
    pthread_mutex_lock(&job->lock);
    job->metrics = *metrics;
    pthread_mutex_unlock(&job->lock);
}

void nf_job_finish(NfJob *job, NfMetrics *metrics, bool failed)
{
    metrics->ended = nf_now_ms();
    nf_job_publish(job, metrics);
    atomic_store(&job->state, failed ? NF_FAILED :
                 atomic_load(&job->stop) ? NF_STOPPED : NF_FINISHED);
    atomic_store(&job->done, true);
}

const char *nf_job_status(NfJob *job)
{
    if (job->live && atomic_load(&job->stop) && !atomic_load(&job->done))
        return "Stopping";
    switch (atomic_load(&job->state)) {
    case NF_STARTING: return "Starting";
    case NF_RUNNING: return "Running";
    case NF_FINISHED: return "Finished";
    case NF_STOPPED: return "Stopped";
    case NF_FAILED: return "Failed";
    default: return "Ready";
    }
}


bool nf_job_init(NfJob *job, const char *name)
{
    if (!job || !name) return false;
    memset(job, 0, sizeof *job);
    job->name = name;
    atomic_init(&job->stop, false); atomic_init(&job->done, false);
    atomic_init(&job->state, NF_IDLE);
    int error = pthread_mutex_init(&job->lock, NULL);
    if (error) { nf_log_emit(NF_FAILURE, name, "Cannot initialize worker lock: %s", strerror(error)); return false; }
    return true;
}
bool nf_job_start(NfJob *job, void *(*worker)(void *), const void *config,
                  size_t config_size, unsigned total)
{
    if (!job || !worker || job->live || (config_size && !config)) return false;
    NfMetrics metrics = { .total = total, .started = nf_now_ms() };
    if (metrics.started < 0) { nf_log_emit(NF_FAILURE, job->name, "Cannot read monotonic clock."); return false; }
    void *copy = config_size ? malloc(config_size) : NULL;
    if (config_size && !copy) { nf_log_emit(NF_FAILURE, job->name, "Not enough memory for settings."); return false; }
    if (config_size) memcpy(copy, config, config_size);
    job->config = copy;
    nf_job_publish(job, &metrics);
    atomic_store(&job->stop, false); atomic_store(&job->done, false);
    atomic_store(&job->state, NF_STARTING);
    int error = pthread_create(&job->thread, NULL, worker, job);
    if (error) {
        free(job->config); job->config = NULL;
        atomic_store(&job->state, NF_FAILED);
        nf_log_emit(NF_FAILURE, job->name, "Could not start worker: %s", strerror(error));
        return false;
    }
    job->live = true;
    return true;
}
void nf_job_stop(NfJob *job)
{
    if (job && job->live && !atomic_exchange(&job->stop, true))
        nf_log_emit(NF_INFO, job->name, "Stop requested. Closing the current operation...");
}
bool nf_job_join(NfJob *job)
{
    if (!job) return false;
    if (!job->live) return true;
    int error = pthread_join(job->thread, NULL);
    if (error) { nf_log_emit(NF_FAILURE, job->name, "Cannot join worker: %s", strerror(error)); return false; }
    job->live = false;
    free(job->config); job->config = NULL;
    return true;
}
bool nf_job_reap(NfJob *job)
{
    if (!job) return false;
    return !job->live || !atomic_load(&job->done) || nf_job_join(job);
}
bool nf_job_destroy(NfJob *job)
{
    if (!job) return false;
    nf_job_stop(job);
    if (!nf_job_join(job)) return false;
    return pthread_mutex_destroy(&job->lock) == 0;
}
