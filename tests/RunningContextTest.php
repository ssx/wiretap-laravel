<?php

declare(strict_types=1);

use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Ssx\Wiretap\Laravel\Internal\RunningContext;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;

afterEach(fn () => RunningContext::reset());

function fakeQueueJob(string $name): Illuminate\Contracts\Queue\Job
{
    return new class($name) implements Illuminate\Contracts\Queue\Job {
        public function __construct(private string $name)
        {
        }

        public function resolveName(): string
        {
            return $this->name;
        }

        public function uuid(): ?string
        {
            return 'job-uuid';
        }

        public function getJobId(): ?string
        {
            return '1';
        }

        public function payload(): array
        {
            return [];
        }

        public function fire(): void
        {
        }

        public function release($delay = 0): void
        {
        }

        public function isReleased(): bool
        {
            return false;
        }

        public function delete(): void
        {
        }

        public function isDeleted(): bool
        {
            return false;
        }

        public function isDeletedOrReleased(): bool
        {
            return false;
        }

        public function attempts(): int
        {
            return 1;
        }

        public function hasFailed(): bool
        {
            return false;
        }

        public function markAsFailed(): void
        {
        }

        public function fail($e = null): void
        {
        }

        public function maxTries(): ?int
        {
            return null;
        }

        public function maxExceptions(): ?int
        {
            return null;
        }

        public function backoff(): ?int
        {
            return null;
        }

        public function retryUntil(): ?int
        {
            return null;
        }

        public function timeout(): ?int
        {
            return null;
        }

        public function getName(): string
        {
            return $this->name;
        }

        public function getConnectionName(): string
        {
            return 'sync';
        }

        public function getQueue(): string
        {
            return 'default';
        }

        public function getRawBody(): string
        {
            return '';
        }
    };
}

it('names the running artisan command rather than argv', function (): void {
    // argv[1] names the process the call was made from — "queue:work" for
    // every job a worker ever handles, "schedule:run" for every scheduled
    // command — not the thing that caused it.
    $events = $this->app->make('events');

    $events->dispatch(new CommandStarting('reports:generate', new ArrayInput([]), new NullOutput()));

    expect(RunningContext::command())->toBe('reports:generate');

    $events->dispatch(new CommandFinished('reports:generate', new ArrayInput([]), new NullOutput(), 0));

    expect(RunningContext::command())->toBeNull();
});

it('names the job a worker is handling', function (): void {
    $events = $this->app->make('events');
    $job = fakeQueueJob('App\\Jobs\\SyncOrders');

    $events->dispatch(new JobProcessing('sync', $job));

    expect(RunningContext::job())->toBe('App\\Jobs\\SyncOrders');

    $events->dispatch(new JobProcessed('sync', $job));

    expect(RunningContext::job())->toBeNull();
});

it('puts both on the recorded context', function (): void {
    $events = $this->app->make('events');
    $events->dispatch(new CommandStarting('queue:work', new ArrayInput([]), new NullOutput()));
    $events->dispatch(new JobProcessing('sync', fakeQueueJob('App\\Jobs\\SyncOrders')));

    $enricher = new Ssx\Wiretap\Laravel\LaravelContextEnricher();
    $method = new ReflectionMethod($enricher, 'consoleContext');
    $method->setAccessible(true);

    $context = $method->invoke($enricher);

    expect($context['command'])->toBe('queue:work')
        ->and($context['job'])->toBe('App\\Jobs\\SyncOrders');
});
