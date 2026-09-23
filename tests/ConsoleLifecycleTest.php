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
 * @return array{exit: int, signal: int, output: string, records: list<array<string, mixed>>}
 */
function runConsoleFixture(string $command, bool $enabled = true): array
{
    $path = sys_get_temp_dir() . '/wiretap-console-' . bin2hex(random_bytes(6));

    $process = proc_open(
        [PHP_BINARY, __DIR__ . '/Fixtures/console.php', $command],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        null,
        ['WIRETAP_PATH' => $path, 'WIRETAP_ENABLED' => $enabled ? 'true' : 'false', 'PATH' => (string) getenv('PATH')],
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

final class LifecycleQueuedJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    /** @var array<string, string> */
    public static array $ids = [];

    public function __construct(public string $name)
    {
    }

    public function handle(): void
    {
        Http::get('https://api.example.test/job/' . $this->name);
        self::$ids[$this->name] = Correlation::id();
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

    it('still flushes a command killed by SIGTERM, and still dies by that signal', function (): void {
        // Without wiretap the default disposition kills the process by the
        // signal; a flush must not turn that into an ordinary exit code.
        $run = runConsoleFixture('fixture:plain');

        expect($run['output'])->not->toContain('survived')
            ->and($run['signal'])->toBe(SIGTERM)
            ->and($run['records'])->toHaveCount(1);
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

    it('installs nothing when capture is off', function (): void {
        pcntl_async_signals(true);

        $this->bootWith(['wiretap.enabled' => false]);
        $this->app->make('events')->dispatch(new CommandStarting('anything', new ArrayInput([]), new NullOutput()));

        expect(pcntl_signal_get_handler(SIGTERM))->toBe(SIG_DFL)
            ->and(pcntl_signal_get_handler(SIGINT))->toBe(SIG_DFL);
    });
});

describe('queue workers', function (): void {
    it('gives each job under a real queue:work its own correlation and flush', function (): void {
        // The console listener started an explicit correlation for queue:work
        // itself, so every job declined ownership: one id for the whole
        // worker, and nothing written until the worker exited. Only visible
        // with Symfony's console events rerouted, as a real artisan does.
        $kernel = $this->app->make(ConsoleKernel::class);
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
        LifecycleQueuedJob::dispatch('a');
        LifecycleQueuedJob::dispatch('b');

        $started = false;
        Event::listen(\Illuminate\Console\Events\CommandStarting::class, function () use (&$started): void {
            $started = true;
        });

        $onDiskBeforeSecond = null;
        $path = $this->logPath;
        Event::listen(JobProcessing::class, function () use (&$onDiskBeforeSecond, $path): void {
            if (count(LifecycleQueuedJob::$ids) === 1) {
                $onDiskBeforeSecond = (glob($path . '/*.ndjson') ?: []) !== [];
            }
        });

        Artisan::call('queue:work', ['connection' => 'database', '--stop-when-empty' => true, '--sleep' => 0]);

        expect($started)->toBeTrue()
            ->and(LifecycleQueuedJob::$ids)->toHaveCount(2)
            ->and(LifecycleQueuedJob::$ids['a'])->not->toBe(LifecycleQueuedJob::$ids['b'])
            ->and($onDiskBeforeSecond)->toBeTrue();
    });
});
