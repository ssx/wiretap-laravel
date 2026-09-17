<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel;

use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;
use Ssx\Wiretap\Blocklist\ArrayBlocklistProvider;
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

        $this->app->singleton(NdjsonReader::class, fn (): NdjsonReader => new NdjsonReader(
            (string) config('wiretap.path'),
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
        Wiretap::setRecorder($recorder);

        if (!config('wiretap.enabled')) {
            return;
        }

        $this->registerCorrelationMiddleware();
        $this->attachCaptureSurfaces($recorder);
    }

    private function buildRecorder(): Recorder
    {
        /** @var array<string, mixed> $config */
        $config = config('wiretap');
        $enabled = (bool) ($config['enabled'] ?? false);

        /** @var array<string, mixed> $redaction */
        $redaction = $config['redaction'] ?? [];

        $recorder = new Recorder(
            sink: $enabled
                ? new NdjsonFileSink((string) $config['path'])
                : new NullSink(),
            blocklist: $this->buildBlocklist($config),
            redactor: new Redactor(new RedactionConfig(
                enabled: (bool) ($redaction['enabled'] ?? true),
                bodyPaths: array_values((array) ($redaction['body_paths'] ?? [])),
                maxBodyBytes: (int) ($redaction['max_body_bytes'] ?? 65536),
            )),
            sampler: new Sampler(
                rateBasisPoints: (int) ($config['sample_rate_basis_points'] ?? 10000),
                alwaysKeepFailures: (bool) ($config['always_keep_failures'] ?? true),
                slowThresholdUs: $config['slow_threshold_us'] === null
                    ? null
                    : (int) $config['slow_threshold_us'],
            ),
            enabled: $enabled,
        );

        return $recorder->addEnricher(new LaravelContextEnricher($this->app));
    }

    /**
     * @param array<string, mixed> $config
     */
    private function buildBlocklist(array $config): Blocklist
    {
        return new Blocklist([
            new PresetBlocklistProvider(array_values((array) ($config['presets'] ?? []))),
            new ArrayBlocklistProvider(
                array_values(array_filter(
                    (array) ($config['blocklist'] ?? []),
                    static fn (mixed $p): bool => is_string($p) && trim($p) !== '',
                )),
                'config:wiretap.blocklist',
            ),
            new EnvBlocklistProvider(),
        ]);
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

    private function attachCaptureSurfaces(Recorder $recorder): void
    {
        /** @var array<string, mixed> $capture */
        $capture = (array) config('wiretap.capture', []);

        // globalMiddleware pushes onto the stack every PendingRequest builds.
        //
        // NOT globalOptions(['handler' => ...]): that *replaces* the handler,
        // including the one Http::fake() installs, which would silently break
        // every Http::fake() in the host application's test suite. Installing
        // an observability package must not change how anyone's tests behave.
        if (($capture['http_client'] ?? true) && class_exists(Http::class)) {
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
            $this->app->bind(GuzzleClient::class, static fn (): GuzzleClient => new GuzzleClient([
                'handler' => Stack::wrap(static fn (): Recorder => Wiretap::recorder()),
            ]));
        }
    }
}
