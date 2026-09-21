<?php

declare(strict_types=1);

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Ssx\Wiretap\Correlation;

final class FailingSyncJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    /** @var array<string, string> */
    public static array $seen = [];

    public function handle(): void
    {
        self::$seen['handle'] = Correlation::id();

        throw new RuntimeException('job blew up');
    }

    public function failed(\Throwable $e): void
    {
        // A failure notification sent from here belongs to the same trace.
        self::$seen['failed'] = Correlation::id();
    }
}

final class QuietSyncJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(): void
    {
        // Nothing; the point is what the listener does around it.
    }
}

beforeEach(function (): void {
    FailingSyncJob::$seen = [];
});

it('keeps the job correlation through a sync failure callback', function (): void {
    // SyncQueue raises JobExceptionOccurred, then calls fail(), which invokes
    // failed() and only then raises JobFailed. Finishing on the first event
    // reset the correlation before failed() ran, so a failure-notification
    // call made from there left the trace.
    try {
        FailingSyncJob::dispatchSync();
    } catch (\Throwable) {
        // SyncQueue rethrows; the application sees its own exception.
    }

    expect(FailingSyncJob::$seen)->toHaveKeys(['handle', 'failed'])
        ->and(FailingSyncJob::$seen['failed'])->toBe(FailingSyncJob::$seen['handle']);
});

it('does not write to disk for a job an enclosing scope owns', function (): void {
    // dispatchSync() from inside a request used to put a synchronous
    // NdjsonFileSink write on the request path, which core's Recorder
    // explicitly warns against.
    //
    // Observed from inside the route, immediately after the dispatch: by the
    // time the response comes back the request's own terminating callback has
    // flushed, so the file exists either way and proves nothing.
    Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));

    $path = $this->logPath;
    $wroteDuringRequest = null;

    Route::get('/sync-dispatch', function () use ($path, &$wroteDuringRequest) {
        // An outbound call first, so there is something buffered for the
        // nested job's completion to flush.
        Http::get('https://api.example.com/before-dispatch');

        QuietSyncJob::dispatchSync();

        $wroteDuringRequest = (glob($path . '/*.ndjson') ?: []) !== [];

        return response()->json(['ok' => true]);
    });

    $this->get('/sync-dispatch')->assertOk();

    expect($wroteDuringRequest)->toBeFalse();
});
