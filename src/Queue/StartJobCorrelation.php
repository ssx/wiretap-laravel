<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Queue;

use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Ssx\Wiretap\Correlation;

/**
 * Gives each queued job its own correlation.
 *
 * Correlation was seeded only by HTTP middleware, so in a persistent
 * queue:work process every job shared one id and an ever-growing sequence —
 * and sampling, being deterministic on that id, treated the whole worker as a
 * single unit.
 *
 * Two cases make this less trivial than it looks:
 *
 *  - A job that throws with retries remaining emits neither JobProcessed nor
 *    JobFailed, only JobExceptionOccurred. Listening to the first two alone
 *    left the depth counter permanently unbalanced, so every later job
 *    inherited the failed attempt's correlation.
 *  - A synchronous job dispatched inside an HTTP request must not replace the
 *    request's correlation. It is part of that request, and taking it over
 *    broke request-wide sampling. Only a job with no correlation already in
 *    scope starts a new one.
 */
final class StartJobCorrelation
{
    private int $depth = 0;

    private bool $startedHere = false;

    public function processing(JobProcessing $event): void
    {
        if ($this->depth++ > 0) {
            return;
        }

        // An enclosing scope — an HTTP request, or a console command that set
        // one — owns the correlation. A sync job inside it is part of the same
        // operation.
        if (Correlation::hasStarted()) {
            $this->startedHere = false;

            return;
        }

        $this->startedHere = true;
        Correlation::start($event->job->uuid() ?? null);
    }

    public function processed(JobProcessed $event): void
    {
        $this->finish();
    }

    public function failed(JobFailed $event): void
    {
        $this->finish();
    }

    /**
     * Fires when a job throws but may still be retried. Neither JobProcessed
     * nor JobFailed follows it, so without this the depth never comes back
     * down.
     */
    public function exceptionOccurred(JobExceptionOccurred $event): void
    {
        $this->finish();
    }

    private function finish(): void
    {
        if ($this->depth === 0) {
            // Already balanced — JobFailed can follow JobExceptionOccurred for
            // the same attempt, and the second must not unwind a scope it does
            // not own.
            return;
        }

        $this->depth = max(0, $this->depth - 1);

        if ($this->depth === 0 && $this->startedHere) {
            Correlation::reset();
            $this->startedHere = false;
        }
    }
}
