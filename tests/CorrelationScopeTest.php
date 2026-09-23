<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Laravel\Internal\RunningContext;
use Ssx\Wiretap\Wiretap;

/**
 * Records on disk right now, keyed by URI. Deliberately no flush first:
 * several tests are about what reached the disk without one.
 *
 * @return array<string, array<string, mixed>>
 */
function scopeRecordsOnDisk(string $path): array
{
    $records = [];

    foreach (glob($path . '/*.ndjson') ?: [] as $file) {
        foreach (file($file) ?: [] as $line) {
            $record = json_decode($line, true);
            $records[$record['uri']] = $record;
        }
    }

    return $records;
}

final class ScopeFailingJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(): void
    {
        throw new RuntimeException('failed on purpose');
    }
}

final class ScopeInnerJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(): void
    {
        Http::get('https://api.example.test/inner');
    }
}

final class ScopeOuterJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(): void
    {
        Http::get('https://api.example.test/outer-before');
        ScopeInnerJob::dispatchSync();
        Http::get('https://api.example.test/outer-after');
    }
}

beforeEach(function (): void {
    Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
});

afterEach(fn () => RunningContext::reset());

describe('a nested HTTP request', function (): void {
    it('leaves the outer request\'s correlation and sequence intact', function (): void {
        // The middleware called Correlation::start() again for the inner
        // request, so the outer request's remaining calls carried the inner
        // id, restarted at sequence 0, and fell out of their own trace.
        Route::get('/inner', function () {
            Http::get('https://api.example.test/during-inner');

            return 'inner';
        });

        Route::get('/outer', function () {
            Http::get('https://api.example.test/before');
            app(HttpKernel::class)->handle(Request::create('/inner', 'GET', server: ['HTTP_X_REQUEST_ID' => 'inner-id']));
            Http::get('https://api.example.test/after');

            return 'outer';
        });

        $this->get('/outer', ['X-Request-Id' => 'outer-id'])->assertOk();

        $records = scopeRecordsOnDisk($this->logPath);
        $before = $records['https://api.example.test/before'];
        $after = $records['https://api.example.test/after'];

        expect($before['correlation_id'])->toBe('outer-id')
            ->and($after['correlation_id'])->toBe('outer-id')
            ->and($after['sequence'])->toBeGreaterThan($before['sequence'])
            ->and($records['https://api.example.test/during-inner']['correlation_id'])->toBe('outer-id')
            ->and(array_unique(array_column($records, 'sequence')))->toHaveCount(3);
    });
});

describe('terminating callbacks', function (): void {
    it('keep the request\'s correlation and are flushed, when registered after ours', function (): void {
        // Ours flushed and reset the correlation. One an application
        // registers afterwards — every AppServiceProvider::boot() — ran with
        // a fresh, unrelated id, and its record sat in the buffer until some
        // later request flushed it.
        $this->app->terminating(fn () => Http::post('https://metrics.example.test/request-finished'));

        Route::get('/checkout', function () {
            Http::get('https://api.example.test/charge');

            return 'ok';
        });

        $this->get('/checkout', ['X-Request-Id' => 'checkout-id'])->assertOk();

        $records = scopeRecordsOnDisk($this->logPath);

        expect($records)->toHaveKeys([
            'https://api.example.test/charge',
            'https://metrics.example.test/request-finished',
        ])
            ->and($records['https://metrics.example.test/request-finished']['correlation_id'])->toBe('checkout-id');
    });

    it('still end the request\'s correlation scope', function (): void {
        Route::get('/ok', fn () => 'ok');

        $this->get('/ok', ['X-Request-Id' => 'scoped'])->assertOk();

        expect(Correlation::startedExplicitly())->toBeFalse()
            ->and(Correlation::hasStarted())->toBeFalse();
    });

    it('register the final flush once, however many requests are served', function (): void {
        Route::get('/ok', fn () => 'ok');

        foreach (range(1, 5) as $_) {
            $this->get('/ok')->assertOk();
        }

        $kernel = app(HttpKernel::class);
        $handlers = (new ReflectionProperty($kernel, 'requestLifecycleDurationHandlers'))->getValue($kernel);

        expect($handlers)->toHaveCount(1);
    });
});

describe('the job named on a record', function (): void {
    it('is cleared after a failed job', function (): void {
        // Only JobProcessed cleared it, so every call after a failed job was
        // attributed to that job.
        try {
            ScopeFailingJob::dispatchSync();
        } catch (\Throwable) {
        }

        Http::get('https://api.example.test/later');
        Wiretap::recorder()->flush();

        expect(scopeRecordsOnDisk($this->logPath)['https://api.example.test/later']['context'])->not->toHaveKey('job');
    });

    it('goes back to the outer job after a nested one', function (): void {
        // The inner job's JobProcessed set it to null, so the outer job's
        // remaining calls named no job at all.
        ScopeOuterJob::dispatchSync();
        Wiretap::recorder()->flush();

        $records = scopeRecordsOnDisk($this->logPath);

        expect($records['https://api.example.test/outer-before']['context']['job'])->toBe(ScopeOuterJob::class)
            ->and($records['https://api.example.test/inner']['context']['job'])->toBe(ScopeInnerJob::class)
            ->and($records['https://api.example.test/outer-after']['context']['job'])->toBe(ScopeOuterJob::class);
    });

    it('is popped once when a worker job raises both an exception and a failure', function (): void {
        // A non-sync job that fails for good fires JobExceptionOccurred and
        // JobFailed. Popping on both would take the enclosing job's name too.
        $events = $this->app->make('events');
        $job = function (string $name): Illuminate\Contracts\Queue\Job {
            $job = Mockery::mock(Illuminate\Contracts\Queue\Job::class);
            $job->shouldReceive('resolveName')->andReturn($name);
            $job->shouldReceive('uuid')->andReturn(null);
            $job->shouldIgnoreMissing();

            return $job;
        };
        $outer = $job('App\\Jobs\\Outer');
        $inner = $job('App\\Jobs\\Inner');

        $events->dispatch(new JobProcessing('redis', $outer));
        $events->dispatch(new JobProcessing('redis', $inner));
        $events->dispatch(new JobExceptionOccurred('redis', $inner, new RuntimeException('x')));

        expect(RunningContext::job())->toBe('App\\Jobs\\Outer');

        $events->dispatch(new JobFailed('redis', $inner, new RuntimeException('x')));

        expect(RunningContext::job())->toBe('App\\Jobs\\Outer');
    });
});

describe('user attribution', function (): void {
    it('comes from the guard the request is acting through', function (): void {
        // The first guard AuthManager had cached won, so an admin acting on a
        // customer's session was recorded as the customer.
        config(['auth.guards.admin' => ['driver' => 'session', 'provider' => 'users']]);

        Route::get('/admin/refund', function () {
            Auth::guard('web')->setUser(new GenericUser(['id' => 1]));
            Auth::guard('admin')->setUser(new GenericUser(['id' => 7]));
            Auth::shouldUse('admin');
            Http::get('https://api.example.test/refund');

            return 'ok';
        });

        $this->get('/admin/refund')->assertOk();

        expect(scopeRecordsOnDisk($this->logPath)['https://api.example.test/refund']['context']['user_id'])->toBe(7);
    });

    it('is omitted when the acting guard has not been resolved', function (): void {
        // Another guard having a user says nothing about who is acting now.
        config(['auth.guards.admin' => ['driver' => 'session', 'provider' => 'users']]);

        Route::get('/mixed', function () {
            Auth::guard('admin')->setUser(new GenericUser(['id' => 7]));
            Http::get('https://api.example.test/mixed');

            return 'ok';
        });

        $this->get('/mixed')->assertOk();

        expect(scopeRecordsOnDisk($this->logPath)['https://api.example.test/mixed']['context'])->not->toHaveKey('user_id');
    });
});
