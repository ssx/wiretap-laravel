<?php

declare(strict_types=1);

/*
 * A real console process, for behaviour the test kernel cannot show.
 *
 * Laravel only routes Symfony's console events to CommandStarting and
 * CommandFinished when the application is not running unit tests, so inside
 * testbench neither fires for a real command. Signals cannot be exercised
 * in-process either: a handler that terminates would take the test runner
 * with it. This boots an application with APP_ENV=local and runs one command,
 * exactly as `php artisan` would.
 *
 * Usage: php console.php <command> [args]   (WIRETAP_PATH, WIRETAP_ENABLED,
 *        WIRETAP_FIXTURE_URL from env)
 */

putenv('APP_ENV=local');
$_ENV['APP_ENV'] = $_SERVER['APP_ENV'] = 'local';

require __DIR__ . '/../../vendor/autoload.php';

use Illuminate\Console\Application as Artisan;
use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Http;
use Symfony\Component\Console\Command\SignalableCommandInterface;

/** Make one captured call, so there is something buffered to lose. */
function wiretapFixtureCall(): void
{
    Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
    Http::get('https://api.example.test/fixture');
}

Artisan::starting(function (Artisan $artisan): void {
    // An application's own graceful shutdown via trap().
    $artisan->add(new class extends Command {
        protected $signature = 'fixture:trap';

        public function handle(): int
        {
            $stop = false;
            $this->trap([SIGTERM], function () use (&$stop): void {
                $stop = true;
            });

            wiretapFixtureCall();
            posix_kill(posix_getpid(), SIGTERM);

            for ($i = 0; $i < 100 && !$stop; $i++) {
                usleep(10000);
            }

            $this->line('cleanup ran, stop=' . var_export($stop, true));

            return 0;
        }
    });

    // ...and via Symfony's SignalableCommandInterface.
    $artisan->add(new class extends Command implements SignalableCommandInterface {
        protected $signature = 'fixture:signalable';

        private bool $stop = false;

        public function getSubscribedSignals(): array
        {
            return [SIGINT, SIGTERM];
        }

        public function handleSignal(int $signal, int|false $previousExitCode = 0): int|false
        {
            $this->stop = true;

            return false;
        }

        public function handle(): int
        {
            wiretapFixtureCall();
            posix_kill(posix_getpid(), SIGINT);

            for ($i = 0; $i < 100 && !$this->stop; $i++) {
                usleep(10000);
            }

            $this->line('cleanup ran, stop=' . var_export($this->stop, true));

            return 0;
        }
    });

    // Several completed calls, then killed by a process manager mid-run.
    $artisan->add(new class extends Command {
        protected $signature = 'fixture:calls {count=3}';

        public function handle(): int
        {
            Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));

            for ($i = 0; $i < (int) $this->argument('count'); $i++) {
                Http::get('https://api.example.test/call/' . $i);
            }

            posix_kill(posix_getpid(), SIGTERM);
            usleep(1_000_000);
            $this->line('survived SIGTERM');

            return 0;
        }
    });

    // A raw curl call, seen only by wiretap-auto's hooks, then killed.
    $artisan->add(new class extends Command {
        protected $signature = 'fixture:curl';

        public function handle(): int
        {
            $handle = curl_init((string) getenv('WIRETAP_FIXTURE_URL'));
            curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
            curl_exec($handle);

            posix_kill(posix_getpid(), SIGTERM);
            usleep(1_000_000);
            $this->line('survived SIGTERM');

            return 0;
        }
    });

    // A command that handles nothing, killed by a process manager.
    $artisan->add(new class extends Command {
        protected $signature = 'fixture:plain';

        public function handle(): int
        {
            wiretapFixtureCall();
            posix_kill(posix_getpid(), SIGTERM);

            for ($i = 0; $i < 100; $i++) {
                usleep(10000);
            }

            $this->line('survived SIGTERM');

            return 0;
        }
    });
});

$app = Orchestra\Testbench\Foundation\Application::create(
    resolvingCallback: function ($app): void {
        $app->afterBootstrapping(
            Orchestra\Testbench\Bootstrap\LoadConfiguration::class,
            function ($app): void {
                $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
                $app['config']->set('wiretap.enabled', getenv('WIRETAP_ENABLED') === 'true');
                $app['config']->set('wiretap.path', (string) getenv('WIRETAP_PATH'));
                $app['config']->set('wiretap.presets', []);
            },
        );
    },
    options: ['extra' => [
        'dont-discover' => ['*'],
        'providers' => [Ssx\Wiretap\Laravel\WiretapServiceProvider::class],
    ]],
);

$kernel = $app->make(Kernel::class);
$input = new Symfony\Component\Console\Input\ArgvInput();
$status = $kernel->handle($input, new Symfony\Component\Console\Output\ConsoleOutput());
$kernel->terminate($input, $status);

exit($status);
