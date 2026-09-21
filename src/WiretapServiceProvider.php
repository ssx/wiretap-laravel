<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Blocklist\Blocklist;
use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Guzzle\WiretapMiddleware;
use Ssx\Wiretap\Laravel\Console\DoctorCommand;
use Ssx\Wiretap\Laravel\Console\ExportCommand;
use Ssx\Wiretap\Laravel\Console\ListCommand;
use Ssx\Wiretap\Laravel\Console\PruneCommand;
use Ssx\Wiretap\Laravel\Console\ShowCommand;
use Ssx\Wiretap\Laravel\Console\TraceCommand;
use Ssx\Wiretap\Laravel\Http\StartCorrelation;
use Ssx\Wiretap\Laravel\Queue\StartJobCorrelation;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Sink\NullSink;
use Ssx\Wiretap\Wiretap;

final class WiretapServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/wiretap.php', 'wiretap');

        $this->app->singleton(Recorder::class, fn (): Recorder => $this->buildRecorder());

        $this->app->singleton(StartJobCorrelation::class);

        $this->app->singleton(NdjsonReader::class, fn (): NdjsonReader => new NdjsonReader(
            self::path((array) config('wiretap', [])),
        ));
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/wiretap.php' => $this->app->configPath('wiretap.php'),
        ], 'wiretap-config');

        if ($this->app->runningInConsole()) {
            $this->commands([
                ListCommand::class,
                ShowCommand::class,
                TraceCommand::class,
                ExportCommand::class,
                PruneCommand::class,
                DoctorCommand::class,
            ]);
        }

        $recorder = $this->app->make(Recorder::class);

        // Publish even when disabled. Returning early left whatever the
        // previous application put on the holder — in a worker running several
        // applications, an enabled recorder from an earlier one kept receiving
        // traffic under its own policy.
        //
        // Except while a fake is active. setRecorder() clears it, so a host
        // test doing Wiretap::fake() and then refreshApplication() — or the
        // bootWith() helper in this package's own TestCase — silently lost its
        // double, and the next assertion failed with "Wiretap::fake() must be
        // called before assertions" about traffic that had definitely happened.
        if (!Wiretap::isFaked()) {
            Wiretap::setRecorder($recorder);
        }

        $this->registerCorrelationMiddleware();
        $this->registerQueueCorrelation();
        $this->registerConsoleCorrelation();

        // Octane runs terminating callbacks per request, and a queue worker
        // per job. Without this the recorder flushed only at 200 records, 8
        // MiB, or process exit — so someone enabling capture to debug a job
        // ran wiretap:list, saw nothing, and concluded the tool was broken.
        $this->app->terminating(static function (): void {
            Wiretap::recorder()->flush();

            // Then end the request's correlation scope.
            //
            // Correlation::start() marks the id as explicitly owned, which the
            // queue listener reads as "an enclosing scope owns this". Nothing
            // cleared it, so in any process that serves a request and then does
            // other work — Octane, or a job dispatched from a terminating
            // callback — every job afterwards declined ownership and inherited
            // that request's id, forever: one id, one ever-growing sequence,
            // the wrong route on every record, and one sampling decision for
            // the whole process.
            //
            // Here rather than in the middleware's terminate(): the middleware
            // is prepended, and Kernel::terminateMiddleware() walks the list in
            // order, so resetting there ran before every other terminable
            // middleware. An application shipping metrics over HTTP from one of
            // those would have had each call given a fresh, unrelated id.
            // app()->terminate() runs after all of them.
            Correlation::reset();
        });

        // Surfaces are attached even when capture is disabled.
        //
        // They resolve the recorder per call, and a disabled recorder records
        // nothing — shouldCapture() returns false before anything is read. But
        // skipping installation entirely meant Wiretap::fake() in a test
        // replaced the recorder and then had no capture surface to record
        // through, so assertSent() failed on traffic that had definitely
        // happened. The package's own tests hid that by enabling wiretap in
        // the test environment.
        $this->attachCaptureSurfaces();
    }

    /**
     * Interpret a configured boolean the way an operator means it.
     *
     * Laravel's env() only converts the literal strings true/false/null/empty,
     * so WIRETAP_ENABLED=off arrived as the string 'off' — and (bool) 'off' is
     * true. Capture ran, writing complete request and response bodies to disk,
     * while the operator believed they had turned it off. Core's own doctor
     * uses filter_var and printed "false" at the same time, so the diagnostic
     * agreed with them.
     *
     * Anything filter_var cannot interpret is treated as false: for a switch
     * that governs recording personal data, an unrecognised value must not
     * mean on.
     */
    public static function truthy(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? false;
    }

    /**
     * The configured log directory, never an empty string.
     *
     * A missing or blank path used to become "" through a (string) cast, and
     * the sink then quietly wrote nowhere — capture appeared to be on and
     * produced no records. Falling back to core's own default keeps the two
     * halves of the package agreeing about where records live.
     *
     * @param array<string, mixed> $config
     */
    public static function path(array $config): string
    {
        $path = $config['path'] ?? null;

        return is_string($path) && trim($path) !== '' ? $path : Wiretap::defaultLogPath();
    }

    private function buildRecorder(): Recorder
    {
        /** @var array<string, mixed> $config */
        $config = config('wiretap');
        $enabled = self::truthy($config['enabled'] ?? false);

        /** @var array<string, mixed> $redaction */
        $redaction = $config['redaction'] ?? [];

        // Every key is read with a default.
        //
        // mergeConfigFrom() is skipped entirely once the application has run
        // config:cache, so a config/wiretap.php published from an earlier
        // version of this package is used exactly as it is — missing keys and
        // all. Reading one directly then raised "Undefined array key", which
        // Laravel's error handler turns into an ErrorException, thrown from
        // inside register(). An observability package must not be able to stop
        // the application from booting.
        $recorder = new Recorder(
            sink: $enabled
                ? new NdjsonFileSink(self::path($config))
                : new NullSink(),
            blocklist: $this->buildBlocklist($config),
            redactor: new Redactor(new RedactionConfig(
                enabled: self::truthy($redaction['enabled'] ?? true),
                bodyPaths: array_values((array) ($redaction['body_paths'] ?? [])),
                maxBodyBytes: (int) ($redaction['max_body_bytes'] ?? 65536),
            )),
            sampler: new Sampler(
                rateBasisPoints: (int) ($config['sample_rate_basis_points'] ?? 10000),
                alwaysKeepFailures: (bool) ($config['always_keep_failures'] ?? true),
                slowThresholdUs: ($config['slow_threshold_us'] ?? null) === null
                    ? null
                    : (int) $config['slow_threshold_us'],
            ),
            enabled: $enabled,
        );

        return $recorder->addEnricher(new LaravelContextEnricher());
    }

    /**
     * @param array<string, mixed> $config
     */
    private function buildBlocklist(array $config): Blocklist
    {
        return new Blocklist([
            // Falls back to the payment-gateway preset, not to nothing. Every
            // other key here falls back to its safe value; an absent presets
            // key silently emptying the gate would be the one exception, and
            // the wrong way round.
            new PresetBlocklistProvider(array_values(
                (array) ($config['presets'] ?? [PresetBlocklistProvider::PAYMENT_GATEWAYS]),
            )),
            new ArrayBlocklistProvider(
                self::blocklistEntries((array) ($config['blocklist'] ?? [])),
                'config:wiretap.blocklist',
            ),
            new EnvBlocklistProvider(),
        ]);
    }

    /**
     * The configured blocklist entries, or a refusal.
     *
     * Entries used to be filtered to strings and anything else dropped in
     * silence. The natural typo is a bracket where array_merge belongs:
     *
     *     'blocklist' => [ EnvBlocklistProvider::parse(env('WIRETAP_BLOCK')), '*.acquirer.test' ],
     *
     * whose first element is an array. That entry vanished, Blocklist::errors()
     * stayed empty, and doctor showed a green tick — while the acquirer rule
     * the operator believed was protecting them did not exist. A gate failing
     * open without saying so is the worst outcome available here.
     *
     * Nested arrays are flattened, because that typo has an obvious intent.
     * Anything else throws, which makes core fail closed and block everything
     * until it is fixed. Loud and safe beats quiet and wrong for a control
     * whose job is keeping cardholder data out of the capture.
     *
     * @param  array<array-key, mixed> $entries
     * @return list<string>
     */
    private static function blocklistEntries(array $entries): array
    {
        $flat = [];

        array_walk_recursive($entries, static function (mixed $entry) use (&$flat): void {
            if (!is_string($entry)) {
                throw new \InvalidArgumentException(sprintf(
                    'wiretap.blocklist entries must be strings, found %s. '
                    . 'Blocking all traffic until this is corrected.',
                    get_debug_type($entry),
                ));
            }

            if (trim($entry) !== '') {
                $flat[] = $entry;
            }
        });

        return $flat;
    }

    /**
     * A persistent worker never reaches the HTTP middleware, so without this
     * every job it handles shares one correlation and one sampling decision.
     */
    private function registerQueueCorrelation(): void
    {
        if (!$this->app->bound('events')) {
            return;
        }

        $events = $this->app->make('events');
        $listener = $this->app->make(StartJobCorrelation::class);

        $events->listen(JobProcessing::class, [$listener, 'processing']);
        $events->listen(JobProcessed::class, [$listener, 'processed']);
        $events->listen(JobFailed::class, [$listener, 'failed']);
        // A retryable failure emits only this one.
        $events->listen(JobExceptionOccurred::class, [$listener, 'exceptionOccurred']);
    }

    /**
     * One correlation per artisan command, and a flush when it ends.
     *
     * There was no console lifecycle at all: only HTTP and queue. So every
     * command in a process shared one id and one sampling decision —
     * `schedule:run` made every scheduled command a single "trace", and
     * anything calling Artisan::call() repeatedly did the same. The sequence
     * counter grew without bound and `wiretap trace <id>` returned the whole
     * process.
     *
     * The flush matters as much as the id. A short command never reaches the
     * terminating callback in time to be useful, and a daemon — horizon,
     * schedule:work — never reaches it at all, so records sat in the buffer
     * until the 200-record threshold or process exit, and PHP runs no shutdown
     * functions on the SIGTERM that supervisor and Kubernetes send.
     */
    private function registerConsoleCorrelation(): void
    {
        if (!$this->app->bound('events')) {
            return;
        }

        $events = $this->app->make('events');

        $events->listen(CommandStarting::class, static function (CommandStarting $event): void {
            Correlation::reset();
            Correlation::start();
        });

        $events->listen(CommandFinished::class, static function (CommandFinished $event): void {
            Wiretap::recorder()->flush();
            Correlation::reset();
        });
    }

    private function registerCorrelationMiddleware(): void
    {
        if (!$this->app->bound(Kernel::class)) {
            return;
        }

        $kernel = $this->app->make(Kernel::class);

        // prependMiddleware so the correlation id exists before anything else
        // has a chance to make an outbound call.
        if (method_exists($kernel, 'prependMiddleware')) {
            $kernel->prependMiddleware(StartCorrelation::class);
        }
    }

    /**
     * Whether this Http factory already carries our middleware.
     *
     * Http::globalMiddleware() appends unconditionally, so booting the
     * provider twice — a host test registering it with force, Octane
     * rebooting an application in-process — pushed a second copy, and every
     * outbound call then produced two records, two body captures in memory,
     * and a sequence counting 0 and 1 for the same call.
     *
     * Asked of the factory rather than tracked in a static flag: each
     * application gets a fresh factory, and a process-wide flag meant the
     * second application in a test run installed nothing at all.
     */
    private static function alreadyInstalled(HttpFactory $factory): bool
    {
        foreach ($factory->getGlobalMiddleware() as $middleware) {
            if ($middleware instanceof WiretapMiddleware) {
                return true;
            }
        }

        return false;
    }

    private function attachCaptureSurfaces(): void
    {
        /** @var array<string, mixed> $capture */
        $capture = (array) config('wiretap.capture', []);

        // globalMiddleware pushes onto the stack every PendingRequest builds.
        //
        // NOT globalOptions(['handler' => ...]): that *replaces* the handler,
        // including the one Http::fake() installs, which would silently break
        // every Http::fake() in the host application's test suite. Installing
        // an observability package must not change how anyone's tests behave.
        $factory = class_exists(Http::class) ? Http::getFacadeRoot() : null;

        if (($capture['http_client'] ?? true)
            && $factory instanceof HttpFactory
            && !self::alreadyInstalled($factory)) {
            // Resolved per call, not captured here: middleware is pushed once
            // at boot, and a host application's test calling Wiretap::fake()
            // afterwards must be able to redirect this traffic.
            Http::globalMiddleware(new WiretapMiddleware(static fn (): Recorder => Wiretap::recorder()));
        }

        // Anything resolving Guzzle from the container gets a recorded client.
        // Code doing `new Client()` directly is out of reach — that is what
        // ssx/wiretap-auto exists for.
        //
        // Only when nothing else has bound it. An unconditional bind replaced
        // an application's own client — base_uri, auth, timeouts, certificates,
        // even a test mock handler — with a bare default. That can break
        // production requests and make a test suite hit the network.
        if (($capture['container_guzzle'] ?? true)
            && class_exists(GuzzleClient::class)
            && !$this->app->bound(GuzzleClient::class)) {
            $this->app->bind(
                GuzzleClient::class,
                /**
                 * @param array<string, mixed> $parameters
                 */
                static function ($app, array $parameters = []): GuzzleClient {
                    // Honour make()/makeWith() parameters. Discarding them
                    // meant app(Client::class, ['config' => [...]]) silently
                    // lost base_uri, auth and timeouts that had previously
                    // been passed straight to the constructor.
                    /** @var array<string, mixed> $config */
                    $config = is_array($parameters['config'] ?? null) ? $parameters['config'] : [];

                    $resolver = static fn (): Recorder => Wiretap::recorder();

                    // Attach to a handler the caller supplied rather than
                    // replacing it — whatever shape it is in.
                    //
                    // Only a HandlerStack used to survive. Guzzle accepts any
                    // callable as a handler, so app(Client::class, ['config'
                    // => ['handler' => new MockHandler([...])]]) had its mock
                    // silently swapped for the default transport: a test that
                    // believed it was stubbing traffic made real network
                    // requests instead, and it happened even with capture
                    // disabled.
                    $handler = $config['handler'] ?? null;

                    if ($handler instanceof HandlerStack) {
                        $config['handler'] = Stack::attach($handler, $resolver);
                    } elseif (is_callable($handler)) {
                        $config['handler'] = Stack::attach(HandlerStack::create($handler), $resolver);
                    } else {
                        $config['handler'] = Stack::wrap($resolver);
                    }

                    return new GuzzleClient($config);
                },
            );
        }
    }
}
