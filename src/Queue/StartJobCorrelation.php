<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Queue;

use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\SyncJob;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Laravel\Http\StartCorrelation;
use Ssx\Wiretap\Laravel\Internal\RunningContext;
use Ssx\Wiretap\Wiretap;

/**
 * Gives each queued job its own correlation.
 *
 * Without this, a persistent queue:work process never calls start() or
 * reset(), so every job shares one id and an ever-growing sequence — and
 * sampling, being deterministic on that id, treats the whole worker as a
 * single unit.
 *
 * Ownership is tracked per job rather than with a counter. A bare depth
 * counter was wrong in two ways that only show up in combination:
 *
 *  - SyncQueue fires JobExceptionOccurred *and* JobFailed for the same
 *    attempt. At depth 2 — a sync job dispatched inside another job — both
 *    decremented, the depth hit zero early, and the *outer* job's correlation
 *    was reset out from under it. Every later job then inherited a stale id.
 *  - The listener asked Correlation::hasStarted() to decide whether an
 *    enclosing scope owned the correlation, but that becomes true as soon as
 *    anything calls Correlation::id() — which the capture middleware does on
 *    the first outbound call. One HTTP call at boot meant no job in that
 *    worker ever got its own correlation again.
 *
 * So: a stack keyed by job object, and an explicit request-scope marker.
 */
final class StartJobCorrelation
{
    /** @var list<int> */
    private array $stack = [];

    /** @var array<int, bool> */
    private array $owned = [];

    public function processing(JobProcessing $event): void
    {
        $id = $this->idFor($event->job);

        if (isset($this->owned[$id])) {
            // Same job seen twice without a completion event. Do not stack it
            // again, or the matching completion can never balance.
            return;
        }

        $nested = $this->stack !== [];
        $this->stack[] = $id;

        // The job class, so a worker's records say what actually made the
        // call instead of all reporting "queue:work". A name that cannot be
        // read costs the attribution, never the job.
        try {
            RunningContext::pushJob($id, $event->job->resolveName());
        } catch (\Throwable) {
        }

        // An enclosing scope owns the correlation: an outer job, or an HTTP
        // request that dispatched this one synchronously. A sync job inside a
        // request is part of that request, and taking it over broke
        // request-wide sampling.
        // An enclosing scope owns the correlation when an outer job holds it,
        // an HTTP request is being handled, or something deliberately called
        // Correlation::start(). A correlation that merely got generated on
        // demand by the first outbound call does not count — treating it as an
        // owner meant one HTTP call at boot silenced every job in the worker.
        $this->owned[$id] = !$nested
            && !StartCorrelation::isHandlingRequest()
            && !Correlation::startedExplicitly();

        if ($this->owned[$id]) {
            Correlation::start($event->job->uuid() ?? null);
        }
    }

    public function processed(JobProcessed $event): void
    {
        $this->finish($event->job);
    }

    public function failed(JobFailed $event): void
    {
        $this->finish($event->job);
    }

    /**
     * Fires when a job throws but may still be retried, and — for the sync
     * queue — alongside JobFailed for the same attempt.
     *
     * A sync job is left alone here. SyncQueue raises this event, then calls
     * fail(), which invokes the job's own failed() callback and only then
     * raises JobFailed — so finishing on this event reset the correlation
     * before failed() ran. A failure-notification HTTP call made from there
     * got a fresh unrelated id and dropped out of the trace, and the
     * JobFailed that followed skipped flushing those captures because
     * ownership had already been given up. For a sync job a JobFailed always
     * follows, so deferring to it loses nothing.
     */
    public function exceptionOccurred(JobExceptionOccurred $event): void
    {
        if ($event->job instanceof SyncJob) {
            return;
        }

        $this->finish($event->job);
    }

    /**
     * Whether a job is being processed right now.
     */
    public function inJob(): bool
    {
        return $this->stack !== [];
    }

    private function finish(Job $job): void
    {
        $id = $this->idFor($job);

        if (!isset($this->owned[$id])) {
            // Already completed — the second of a JobExceptionOccurred /
            // JobFailed pair. Unwinding again would pop a scope belonging to
            // the job outside this one.
            return;
        }

        $owned = $this->owned[$id];
        unset($this->owned[$id]);

        RunningContext::popJob($id);

        $position = array_search($id, $this->stack, true);

        if ($position !== false) {
            array_splice($this->stack, $position, 1);
        }

        if (!$owned) {
            // An enclosing scope — a request, or an outer job — owns this one
            // and will flush when it ends. Flushing here put a synchronous
            // NdjsonFileSink write on the request path for every job
            // dispatched with dispatchSync() from a controller, which is
            // exactly what core's Recorder warns against.
            return;
        }

        // Flush per job. A worker otherwise held captures until 200 records, 8
        // MiB or process exit, so someone enabling capture to debug one job
        // ran wiretap:list and saw nothing.
        Wiretap::recorder()->flush();

        Correlation::reset();
    }

    private function idFor(Job $job): int
    {
        return spl_object_id($job);
    }
}
