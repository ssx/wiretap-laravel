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
use Ssx\Wiretap\Laravel\Internal\RunningContext;
use Ssx\Wiretap\Laravel\Queue\StartJobCorrelation;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;
use Ssx\Wiretap\Sampler;
use Ssx\Wiretap\Sink\NdjsonFileSink;
use Ssx\Wiretap\Sink\NullSink;
use Ssx\Wiretap\Wiretap;
use Symfony\Component\Console\SignalRegistry\SignalRegistry;

final class WiretapServiceProvider extends ServiceProvider
{
    /**
     * Commands that run jobs, each of which gets its own correlation.
     */
    private const WORKER_COMMANDS = ['queue:work', 'queue:listen', 'horizon:work'];

    /**
     * The flush handler installed per signal, so it can recognise itself.
     *
     * @var array<int, \Closure>
     */
    private static array $signalHandlers = [];

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
        $this->registerSignalFlush();

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
     * The secret the sampling decision is keyed with.
     *
     * Sampling is deterministic on the correlation id, and StartCorrelation
     * adopts an inbound traceparent or X-Request-Id so a trace joins up with
     * whatever called us. That makes the sampling key caller-controlled: below
     * 100% a caller who knows the algorithm can compute an id that keeps their
     * own traffic out of the capture, or collide with another request's id.
     *
     * Keying the decision with the application key fixes that without giving
     * anything up — the id is still recorded exactly as it arrived, so traces
     * still join; only the key the decision is computed from changes. The
     * application key is already a per-install secret that must not leak, so
     * it needs no new configuration and nothing extra to rotate.
     *
     * A dedicated `sampling_salt` overrides it for anyone who would rather not
     * derive anything else from `app.key`. Null when neither is set, which is
     * core's previous behaviour and fine at 100% sampling or where nothing
     * untrusted reaches the correlation id.
     *
     * @param array<string, mixed> $config
     */
    private static function samplingSalt(array $config): ?string
    {
        $configured = $config['sampling_salt'] ?? null;

        if (is_string($configured) && trim($configured) !== '') {
            return $configured;
        }

        $key = config('app.key');

        return is_string($key) && trim($key) !== '' ? $key : null;
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
            redactor: new Redactor($this->redactionConfig($redaction)),
            sampler: new Sampler(
                rateBasisPoints: (int) ($config['sample_rate_basis_points'] ?? 10000),
                alwaysKeepFailures: (bool) ($config['always_keep_failures'] ?? true),
                slowThresholdUs: ($config['slow_threshold_us'] ?? null) === null
                    ? null
                    : (int) $config['slow_threshold_us'],
                samplingSalt: self::samplingSalt($config),
            ),
            enabled: $enabled,
        );

        return $recorder->addEnricher(new LaravelContextEnricher());
    }

    /**
     * The redaction rules, with every option the core config exposes.
     *
     * Only enabled, body_paths and max_body_bytes used to be passed through,
     * so ten of core's options had no config key at all. An application whose
     * partner API authenticates with `X-Partner-Secret` could not add that
     * header to the denylist — it was captured in full and nothing in Laravel
     * could stop it — and `patterns.email` could not be turned on, which
     * matters because a string user identifier can be an email address.
     *
     * Lists merge with core's defaults rather than replacing them. Replacing
     * would mean naming one extra sensitive header silently dropped
     * Authorization, Cookie and the rest, which is the opposite of what
     * someone adding a header to a denylist is asking for. `patterns` is
     * merged by key so a single detector can be flipped without restating
     * the others.
     *
     * @param array<string, mixed> $redaction
     */
    private function redactionConfig(array $redaction): RedactionConfig
    {
        /** @var array<string, mixed> $patterns */
        $patterns = (array) ($redaction['patterns'] ?? []);

        $defaults = new RedactionConfig();

        return new RedactionConfig(
            enabled: self::truthy($redaction['enabled'] ?? true),
            headerMode: is_string($redaction['header_mode'] ?? null)
                ? $redaction['header_mode']
                : $defaults->headerMode,
            // Core's own lists are lowercase and it matches case-insensitively,
            // so configured names are lowered before merging — otherwise
            // 'Authorization' and 'authorization' both end up in the list.
            headers: self::mergeList($defaults->headers, $redaction['headers'] ?? [], lower: true),
            query: self::mergeList($defaults->query, $redaction['query'] ?? [], lower: true),
            bodyPaths: array_values((array) ($redaction['body_paths'] ?? [])),
            patterns: array_merge($defaults->patterns, array_filter(
                $patterns,
                static fn (mixed $v): bool => is_bool($v),
            )),
            custom: self::mergeList([], $redaction['custom'] ?? []),
            safetyNet: self::truthy($redaction['safety_net'] ?? true),
            capturableTypes: self::mergeList($defaults->capturableTypes, $redaction['capturable_types'] ?? []),
            maxBodyBytes: (int) ($redaction['max_body_bytes'] ?? $defaults->maxBodyBytes),
            maxHeaderValueBytes: (int) ($redaction['max_header_value_bytes'] ?? $defaults->maxHeaderValueBytes),
            minEchoedSecretLength: (int) ($redaction['min_echoed_secret_length'] ?? $defaults->minEchoedSecretLength),
            omitUninspectableBodies: self::truthy($redaction['omit_uninspectable_bodies'] ?? true),
        );
    }

    /**
     * Configured strings added to core's defaults, de-duplicated.
     *
     * @param  list<string> $defaults
     * @return list<string>
     */
    private static function mergeList(array $defaults, mixed $configured, bool $lower = false): array
    {
        $extra = array_values(array_filter(
            (array) $configured,
            static fn (mixed $v): bool => is_string($v) && trim($v) !== '',
        ));

        if ($lower) {
            $extra = array_map(static fn (string $v): string => strtolower(trim($v)), $extra);
        }

        return array_values(array_unique(array_merge($defaults, $extra)));
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

        $events->listen(JobProcessing::class, static function (JobProcessing $event): void {
            // The job class, so a worker's records say what actually made the
            // call instead of all reporting "queue:work".
            RunningContext::job($event->job->resolveName(), set: true);
        });
        $events->listen(JobProcessing::class, [$listener, 'processing']);
        $events->listen(JobProcessed::class, [$listener, 'processed']);
        $events->listen(JobProcessed::class, static fn (): ?string => RunningContext::job(null, set: true));
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

            // A worker is not one unit of work, and must not own a correlation.
            // Starting one explicitly made the job listener see an enclosing
            // scope for every job, so none took ownership: a real queue:work
            // gave every job the worker's id and one sampling decision, and
            // flushed nothing until it exited. Testbench never showed it,
            // because it does not route Symfony's console events.
            if (!in_array($event->command, self::WORKER_COMMANDS, true)) {
                Correlation::start();
            }

            // So the record names this command rather than argv[1], which in
            // a worker is "queue:work" for every job it ever handles.
            RunningContext::command($event->command, set: true);
        });

        $events->listen(CommandFinished::class, static function (CommandFinished $event): void {
            Wiretap::recorder()->flush();
            Correlation::reset();
            RunningContext::command(null, set: true);
        });
    }

    /**
     * Flush on the signal a process manager sends to stop a daemon.
     *
     * PHP runs no shutdown functions on SIGTERM, and SIGTERM is what
     * supervisor, systemd and Kubernetes send. A long-running console process
     * that is not a queue worker (reverb:start, a custom `while (true)`
     * command) reaches neither CommandFinished nor the terminating callback,
     * so whatever it had buffered was discarded on every restart and deploy.
     *
     * The first version of this took the signal over, and that changed how
     * applications shut down. It exit()ed whenever it found the default
     * disposition behind it — but Symfony's signal registry chains the
     * handler it finds, and Laravel's trap() runs its own callback first and
     * ours after it, so a command that trapped SIGTERM to finish its current
     * unit of work was killed with 143 before it could. It was installed with
     * capture off, and it turned on pcntl_async_signals() for the whole
     * process, letting every handler in it interrupt code that had chosen
     * deferred dispatch.
     *
     * Symfony's own ConsoleEvents::SIGNAL would be the natural hook, but
     * Laravel empties the list of signals it dispatches, so it never fires.
     * So this is installed with the narrowest footprint that still works:
     *
     *  - only with capture on;
     *  - only once a command is starting, when the console application exists
     *    and has already chosen asynchronous delivery itself; with deferred
     *    delivery a handler would hold a SIGTERM the default would have acted
     *    on at once, so nothing is installed;
     *  - only for a signal nobody else handles. An application, a signalable
     *    command, or Octane owning SIGTERM owns it outright.
     *
     * When the signal arrives it flushes, then does whatever would have
     * happened without it. If any other handler shares the signal, that
     * handler decides: we return and the process carries on exactly as it
     * would have. Otherwise the default disposition is restored and the signal
     * re-raised, so the process dies by the signal as it always would have,
     * rather than with an exit code that merely resembles it.
     */
    private function registerSignalFlush(): void
    {
        if (!self::truthy(config('wiretap.enabled'))
            || !$this->app->runningInConsole()
            || !$this->app->bound('events')
            || !function_exists('pcntl_signal')
            || !function_exists('pcntl_async_signals')
            || !function_exists('pcntl_signal_get_handler')
            || !function_exists('posix_kill')
            || !function_exists('posix_getpid')) {
            return;
        }

        $this->app->make('events')->listen(CommandStarting::class, static function (): void {
            self::installSignalFlush();
        });
    }

    private static function installSignalFlush(): void
    {
        // Queried, never set.
        if (!pcntl_async_signals()) {
            return;
        }

        foreach ([SIGTERM, SIGINT] as $signal) {
            // Also the idempotence check: once ours is installed, it is not
            // the default any more.
            if (pcntl_signal_get_handler($signal) !== SIG_DFL) {
                continue;
            }

            $handler = static function (int $received): void {
                try {
                    Wiretap::recorder()->flush();
                } catch (\Throwable) {
                    // Never let instrumentation change how a process dies.
                }

                if (self::signalHandledElsewhere($received)) {
                    return;
                }

                pcntl_signal($received, SIG_DFL);
                posix_kill(posix_getpid(), $received);
            };

            self::$signalHandlers[$signal] = $handler;
            pcntl_signal($signal, $handler);
        }
    }

    /**
     * Whether some other handler shares this signal and so decides its outcome.
     *
     * Symfony's registry calls every handler registered for a signal, and
     * includes the one it found installed — ours — among them. Laravel's
     * trap() reorders that list to run its own callback first. Either way,
     * when the registry holds more than just us, someone else chose to handle
     * the signal and terminating here would overrule them.
     */
    private static function signalHandledElsewhere(int $signal): bool
    {
        // Typed int|string in PHP's stubs; it returns the callable in fact.
        /** @var mixed $current */
        $current = pcntl_signal_get_handler($signal);

        if (is_array($current) && ($current[0] ?? null) instanceof SignalRegistry) {
            // The registry keeps its list private; this is how Laravel's own
            // Signals class reads it too.
            /** @var mixed $handlers */
            $handlers = \Closure::bind(
                static fn (SignalRegistry $registry): mixed => $registry->signalHandlers[$signal] ?? [],
                null,
                SignalRegistry::class,
            )($current[0]);

            return is_array($handlers) && count($handlers) > 1;
        }

        // Called by something that replaced us and chains to us: it decides.
        return $current !== (self::$signalHandlers[$signal] ?? null);
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
