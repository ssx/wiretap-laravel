<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Queue;

use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Ssx\Wiretap\Correlation;

/**
 * Gives each queued job its own correlation.
 *
 * Correlation was seeded only by HTTP middleware. In a persistent queue:work
 * process nothing ever called start() or reset(), so every job the worker
 * handled shared one id and an ever-growing sequence — and because sampling is
 * deterministic on the correlation id, the worker's jobs were sampled together
 * as a single unit rather than independently.
 *
 * A nested synchronous job dispatched inside another keeps the outer
 * correlation: it is part of the same logical operation.
 */
final class StartJobCorrelation
{
    private int $depth = 0;

    public function processing(JobProcessing $event): void
    {
        if ($this->depth++ > 0) {
            return;
        }

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

    private function finish(): void
    {
        $this->depth = max(0, $this->depth - 1);

        if ($this->depth === 0) {
            // Clear between jobs so the next one does not inherit this one's
            // id or sequence.
            Correlation::reset();
        }
    }
}
