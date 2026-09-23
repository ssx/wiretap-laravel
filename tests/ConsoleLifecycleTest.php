<?php

declare(strict_types=1);

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Ssx\Wiretap\Correlation;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;

/**
 * Run tests/Fixtures/console.php as its own process.
 *
 * @param list<string>          $args
 * @param array<string, string> $env
 *
 * @return array{exit: int, signal: int, output: string, records: list<array<string, mixed>>}
 */
function runConsoleFixture(string $command, bool $enabled = true, array $args = [], array $env = []): array
{
    $path = sys_get_temp_dir() . '/wiretap-console-' . bin2hex(random_bytes(6));

    $process = proc_open(
        [PHP_BINARY, __DIR__ . '/Fixtures/console.php', $command, ...$args],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        null,
        ['WIRETAP_PATH' => $path, 'WIRETAP_ENABLED' => $enabled ? 'true' : 'false', 'PATH' => (string) getenv('PATH')] + $env,
    );

    $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);

    // proc_close() cannot tell a signal death from an exit code; the status
    // array can, but only reports it once.
    do {
        $status = proc_get_status($process);
        usleep(5000);
    } while ($status['running']);

    proc_close($process);

    $records = [];

    foreach (glob($path . '/*.ndjson') ?: [] as $file) {
        foreach (file($file) ?: [] as $line) {
            $records[] = json_decode($line, true);
        }

        @unlink($file);
    }

    @rmdir($path);

    return [
        'exit' => $status['signaled'] ? -1 : $status['exitcode'],
        'signal' => $status['signaled'] ? $status['termsig'] : 0,
        'output' => $output,
        'records' => $records,
    ];
}

/**
 * Two jobs through a real worker command, with Symfony's console events
 * rerouted as a real artisan process does.
 *
 * @return array<string, string> correlation id seen by each job
 */
function runRealWorker(Illuminate\Contracts\Foundation\Application $app, string $command): array
{
    $kernel = $app->make(ConsoleKernel::class);
    $kernel->rerouteSymfonyCommandEvents();
    $kernel->setArtisan(null);

    config(['queue.default' => 'database']);
    Schema::create('jobs', function ($table): void {
        $table->id();
        $table->string('queue')->index();
        $table->longText('payload');
        $table->unsignedTinyInteger('attempts');
        $table->unsignedInteger('reserved_at')->nullable();
        $table->unsignedInteger('available_at');
        $table->unsignedInteger('created_at');
    });

    Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
    LifecycleQueuedJob::$ids = [];
    LifecycleQueuedJob::$after = [];
    LifecycleQueuedJob::$onDiskBeforeSecond = null;
    LifecycleQueuedJob::dispatch('a');
    LifecycleQueuedJob::dispatch('b');

    $path = (string) config('wiretap.path');
    Event::listen(JobProcessing::class, function () use ($path): void {
        if (count(LifecycleQueuedJob::$ids) === 1) {
            LifecycleQueuedJob::$onDiskBeforeSecond = (glob($path . '/*.ndjson') ?: []) !== [];
        }
    });

    Artisan::call($command, ['connection' => 'database', '--stop-when-empty' => true, '--sleep' => 0]);

    return LifecycleQueuedJob::$ids;
}

final class LifecycleQueuedJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    /** @var array<string, string> */
    public static array $ids = [];

    /** @var array<string, string> */
    public static array $after = [];

    public static bool $callsCommand = false;

    public static ?bool $onDiskBeforeSecond = null;

    public static bool $twoCalls = false;

    public static ?bool $onDiskBetweenCalls = null;

    public function __construct(public string $name)
    {
    }

    public function handle(): void
    {
        Http::get('https://api.example.test/job/' . $this->name);
        self::$ids[$this->name] = Correlation::id();

        if (self::$twoCalls && $this->name === 'a') {
            self::$onDiskBetweenCalls = (glob((string) config('wiretap.path') . '/*.ndjson') ?: []) !== [];
            Http::get('https://api.example.test/job/' . $this->name . '/again');
        }

        if (self::$callsCommand) {
            Artisan::call('wiretap:doctor');
            self::$after[$this->name] = Correlation::id();
        }
    }
}

describe('signals', function (): void {
    beforeEach(function (): void {
        if (!function_exists('pcntl_signal') || !function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are required');
        }
    });

    afterEach(function (): void {
        if (function_exists('pcntl_signal')) {
            pcntl_signal(SIGTERM, SIG_DFL);
            pcntl_signal(SIGINT, SIG_DFL);
            pcntl_async_signals(false);
        }
    });

    it('lets a command that traps SIGTERM shut down gracefully', function (): void {
        // The flush handler exit()ed with 143 when it was the next handler in
        // line, so the command's own cleanup never ran.
        $run = runConsoleFixture('fixture:trap');

        expect($run['output'])->toContain('cleanup ran, stop=true')
            ->and($run['signal'])->toBe(0)
            ->and($run['exit'])->toBe(0);
    });

    it('lets a signalable command handle SIGINT itself', function (): void {
        $run = runConsoleFixture('fixture:signalable');

        expect($run['output'])->toContain('cleanup ran, stop=true')
            ->and($run['signal'])->toBe(0)
            ->and($run['exit'])->toBe(0);
    });

    it('lets a command killed by SIGTERM die by that signal', function (): void {
        // The old handler turned a signal death into exit(143).
        $run = runConsoleFixture('fixture:plain');

        expect($run['output'])->not->toContain('survived')
            ->and($run['signal'])->toBe(SIGTERM);
    });

    it('keeps every completed call of an ordinary command killed by SIGTERM', function (): void {
        // A command that is not a worker buffered until CommandFinished, and
        // PHP runs no shutdown functions on SIGTERM, so a deploy or scheduler
        // timeout killing a long import lost every call it had made.
        $run = runConsoleFixture('fixture:calls', args: ['5']);

        expect($run['signal'])->toBe(SIGTERM)
            ->and($run['output'])->not->toContain('survived')
            ->and(array_column($run['records'], 'uri'))->toBe(array_map(
                static fn (int $i): string => 'https://api.example.test/call/' . $i,
                range(0, 4),
            ));
    });

    it('keeps a raw curl call recorded by the hooks when killed by SIGTERM', function (): void {
        // The same, for the calls only wiretap-auto sees: vendor code doing
        // its own curl, which no middleware of ours can flush after.
        if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
            $this->markTestSkipped('needs ext-opentelemetry and ssx/wiretap-auto');
        }

        $docroot = sys_get_temp_dir() . '/wiretap-laravel-sigterm-' . bin2hex(random_bytes(4));
        @mkdir($docroot, 0o755, true);
        file_put_contents($docroot . '/index.php', '<?php header("Content-Type: application/json"); echo "{}";');

        $port = 18796;
        $server = proc_open(
            sprintf('exec %s -S 127.0.0.1:%d -t %s', PHP_BINARY, $port, escapeshellarg($docroot)),
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );

        try {
            for ($i = 0; $i < 50 && ($socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1)) === false; $i++) {
                usleep(100_000);
            }

            $run = runConsoleFixture('fixture:curl', env: ['WIRETAP_FIXTURE_URL' => "http://127.0.0.1:{$port}/raw"]);
        } finally {
            proc_terminate($server);
            proc_close($server);
            @unlink($docroot . '/index.php');
            @rmdir($docroot);
        }

        expect($run['signal'])->toBe(SIGTERM)
            ->and(array_column($run['records'], 'uri'))->toBe(["http://127.0.0.1:{$port}/raw"])
            ->and($run['records'][0]['transport'])->toBe('curl');
    });

    it('does not change a killed process when capture is off', function (): void {
        $run = runConsoleFixture('fixture:plain', enabled: false);

        expect($run['signal'])->toBe(SIGTERM)
            ->and($run['records'])->toBe([]);
    });

    it('leaves the application\'s signal dispatch mode alone', function (): void {
        // pcntl_async_signals(true) at registration let every existing handler
        // in the process interrupt code that had chosen deferred dispatch.
        pcntl_async_signals(false);

        $this->refreshApplication();
        $this->app->make('events')->dispatch(new CommandStarting('anything', new ArrayInput([]), new NullOutput()));

        expect(pcntl_async_signals())->toBeFalse()
            ->and(pcntl_signal_get_handler(SIGTERM))->toBe(SIG_DFL);
    });

    it('installs no signal handler at all', function (bool $enabled): void {
        // Any handler changes how some application shuts down: one that
        // switches to deferred dispatch, or chains to the previous handler,
        // had SIGTERM swallowed. So there is none, capture on or off.
        pcntl_async_signals(true);

        $this->bootWith(['wiretap.enabled' => $enabled]);
        $this->app->make('events')->dispatch(new CommandStarting('anything', new ArrayInput([]), new NullOutput()));

        expect(pcntl_signal_get_handler(SIGTERM))->toBe(SIG_DFL)
            ->and(pcntl_signal_get_handler(SIGINT))->toBe(SIG_DFL);
    })->with([[true], [false]]);
});

describe('queue workers', function (): void {
    afterEach(function (): void {
        LifecycleQueuedJob::$callsCommand = false;
    });

    it('gives each job under a real queue:work its own correlation and flush', function (): void {
        // The console listener started an explicit correlation for queue:work
        // itself, so every job declined ownership: one id for the whole
        // worker, and nothing written until the worker exited. Only visible
        // with Symfony's console events rerouted, as a real artisan does.
        $ids = runRealWorker($this->app, 'queue:work');

        expect($ids)->toHaveCount(2)
            ->and($ids['a'])->not->toBe($ids['b'])
            ->and(LifecycleQueuedJob::$onDiskBeforeSecond)->toBeTrue();
    });

    it('treats any WorkCommand as a worker, whatever it is called', function (): void {
        // rabbitmq:consume and an application's own subclasses are workers
        // too; matching by name alone gave them one id for every job.
        Illuminate\Console\Application::starting(function (Illuminate\Console\Application $artisan): void {
            $artisan->add(new class extends Illuminate\Queue\Console\WorkCommand {
                public function __construct()
                {
                    $this->signature = str_replace('queue:work', 'custom:consume', $this->signature);
                    parent::__construct(app('queue.worker'), app('cache.store'));
                }
            });
        });

        $ids = runRealWorker($this->app, 'custom:consume');

        expect($ids['a'])->not->toBe($ids['b']);
    });

    it('keeps a job\'s correlation through a command it calls', function (): void {
        // CommandStarting reset the correlation and CommandFinished reset it
        // again, so a job calling Artisan::call() had its trace cut in two.
        LifecycleQueuedJob::$callsCommand = true;

        $ids = runRealWorker($this->app, 'queue:work');

        expect(LifecycleQueuedJob::$after['a'])->toBe($ids['a'])
            ->and(LifecycleQueuedJob::$after['b'])->toBe($ids['b']);
    });
});

describe('commands called from a request', function (): void {
    it('neither reset the correlation nor flush mid-request', function (): void {
        $kernel = $this->app->make(ConsoleKernel::class);
        $kernel->rerouteSymfonyCommandEvents();
        $kernel->setArtisan(null);

        Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
        $path = $this->logPath;
        $seen = [];

        Illuminate\Support\Facades\Route::get('/calls-a-command', function () use ($path, &$seen) {
            Http::get('https://api.example.test/before');
            $seen['before'] = Correlation::id();
            Artisan::call('wiretap:doctor');
            $seen['after'] = Correlation::id();
            $seen['on_disk'] = (glob($path . '/*.ndjson') ?: []) !== [];

            return 'ok';
        });

        $this->get('/calls-a-command')->assertOk();

        expect($seen['after'])->toBe($seen['before'])
            ->and($seen['on_disk'])->toBeFalse();
    });
});

describe('record batching', function (): void {
    it('still writes nothing during a web request, even after a command ran in-process', function (): void {
        // The per-record writes are for commands only. A request served by a
        // process that had run one — a test suite, a long-lived host — must
        // be back to batching, with no synchronous write on the request path.
        $kernel = $this->app->make(ConsoleKernel::class);
        $kernel->rerouteSymfonyCommandEvents();
        $kernel->setArtisan(null);
        Artisan::call('wiretap:doctor');

        Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
        $path = $this->logPath;
        $onDisk = null;

        Illuminate\Support\Facades\Route::get('/batched', function () use ($path, &$onDisk) {
            Http::get('https://api.example.test/one');
            Http::get('https://api.example.test/two');
            $onDisk = glob($path . '/*.ndjson') ?: [];

            return 'ok';
        });

        $this->get('/batched')->assertOk();

        expect($onDisk)->toBe([])
            ->and(glob($path . '/*.ndjson') ?: [])->not->toBe([]);
    });

    it('still flushes a worker per job rather than per call', function (): void {
        // A worker is not a command in this sense: its jobs keep batching
        // and flush when each one ends.
        LifecycleQueuedJob::$twoCalls = true;

        try {
            runRealWorker($this->app, 'queue:work');
        } finally {
            LifecycleQueuedJob::$twoCalls = false;
        }

        expect(LifecycleQueuedJob::$onDiskBetweenCalls)->toBeFalse()
            ->and(LifecycleQueuedJob::$onDiskBeforeSecond)->toBeTrue();
    });
});
