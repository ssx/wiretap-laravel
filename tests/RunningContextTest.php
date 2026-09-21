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

/**
 * A queue job double.
 *
 * Mocked rather than hand-implemented: the interface gains methods between
 * Laravel majors — 12 added resolveQueuedJobClass() — and an anonymous class
 * implementing it passes on one major and is a fatal error on the next.
 */
function fakeQueueJob(string $name): Illuminate\Contracts\Queue\Job
{
    $job = Mockery::mock(Illuminate\Contracts\Queue\Job::class);
    $job->shouldReceive('resolveName')->andReturn($name);
    $job->shouldReceive('uuid')->andReturn('job-uuid');
    $job->shouldIgnoreMissing();

    return $job;
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
