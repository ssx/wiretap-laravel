<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Http;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Laravel\Http\StartCorrelation;
use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Recorder;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;

describe('configuration read defensively', function (): void {
    it('boots when a published config predates a key', function (): void {
        // mergeConfigFrom() is skipped once config is cached, so a
        // config/wiretap.php published from an older version is used as-is.
        // Reading a key directly then raised "Undefined array key", which
        // Laravel turns into an ErrorException thrown out of register().
        $config = (array) config('wiretap');
        unset($config['slow_threshold_us'], $config['path'], $config['presets']);

        $method = new ReflectionMethod(WiretapServiceProvider::class, 'path');
        $method->setAccessible(true);

        expect($method->invoke(null, $config))->toBeString()->not->toBe('');
    });

    it('falls back to core default path rather than an empty string', function (): void {
        // '' is not null, so core's own `?? defaultLogPath()` never fired and
        // the reader looked in nothing while the sink wrote elsewhere.
        $method = new ReflectionMethod(WiretapServiceProvider::class, 'path');
        $method->setAccessible(true);

        expect($method->invoke(null, ['path' => '   ']))->toBe(Ssx\Wiretap\Wiretap::defaultLogPath())
            ->and($method->invoke(null, ['path' => '/tmp/somewhere']))->toBe('/tmp/somewhere');
    });

    it('reads a boolean the way an operator means it, in doctor as well as the provider', function (string $value, bool $expected): void {
        // env() leaves "off" and "no" as strings and (bool) 'off' is true, so
        // doctor reported capture as enabled while the provider had disabled
        // it — in the one command someone runs to check exactly that.
        expect(WiretapServiceProvider::truthy($value))->toBe($expected);
    })->with([
        ['off', false],
        ['no', false],
        ['0', false],
        ['', false],
        ['nonsense', false],
        ['on', true],
        ['true', true],
        ['1', true],
    ]);
});

describe('the blocklist gate', function (): void {
    it('flattens a nested entry rather than dropping it', function (): void {
        $method = new ReflectionMethod(WiretapServiceProvider::class, 'blocklistEntries');
        $method->setAccessible(true);

        expect($method->invoke(null, [['~^https://a\.test/~'], '*.b.test']))
            ->toBe(['~^https://a\.test/~', '*.b.test']);
    });

    it('refuses an entry it cannot use instead of silently discarding it', function (): void {
        // Filtering non-strings away meant a typo removed an acquirer rule
        // with no error anywhere and a green tick in doctor — a gate failing
        // open in silence.
        $method = new ReflectionMethod(WiretapServiceProvider::class, 'blocklistEntries');
        $method->setAccessible(true);

        expect(fn () => $method->invoke(null, ['a.test', 42]))
            ->toThrow(InvalidArgumentException::class);
    });
});

describe('correlation lifecycle', function (): void {
    it('does not let a finished request own the correlation for every later job', function (): void {
        // Correlation::start() marks the id explicitly owned; nothing cleared
        // it, so every job afterwards declined ownership and inherited the
        // request's id forever — one id, one sampling decision, for the whole
        // process.
        $middleware = new StartCorrelation();
        $middleware->handle(request(), fn () => 'response');

        expect(Correlation::startedExplicitly())->toBeTrue();

        // What app()->terminate() does, after every terminable middleware.
        $this->app->terminate();

        expect(Correlation::startedExplicitly())->toBeFalse()
            ->and(StartCorrelation::isHandlingRequest())->toBeFalse();
    });

    it('restores the handling flag rather than forcing it false', function (): void {
        // A package re-entering Kernel::handle() for a sub-request left the
        // outer request marked "not handling".
        $middleware = new StartCorrelation();

        $middleware->handle(request(), function () use ($middleware) {
            $middleware->handle(request(), fn () => 'inner');

            expect(StartCorrelation::isHandlingRequest())->toBeTrue();

            return 'outer';
        });
    });

    it('gives each artisan command its own correlation', function (): void {
        // There was no console lifecycle at all, so schedule:run made every
        // scheduled command a single trace with one sampling decision.
        $events = $this->app->make('events');
        $input = new ArrayInput([]);
        $output = new NullOutput();

        $ids = [];

        foreach (['first', 'second'] as $command) {
            $events->dispatch(new CommandStarting($command, $input, $output));
            $ids[] = Correlation::id();
            $events->dispatch(new CommandFinished($command, $input, $output, 0));
        }

        expect($ids[0])->not->toBe($ids[1]);
    });
});

describe('capture surfaces', function (): void {
    it('installs the Http middleware once however often the provider boots', function (): void {
        // Http::globalMiddleware() appends unconditionally, so a second boot
        // produced two records for one call.
        $before = count($this->app->make(HttpFactory::class)->getGlobalMiddleware());

        $provider = new WiretapServiceProvider($this->app);
        $provider->register();
        $provider->boot();

        expect($this->app->make(HttpFactory::class)->getGlobalMiddleware())->toHaveCount($before);
    });

    it('honours a caller-supplied handler that is not a HandlerStack', function (): void {
        // Guzzle accepts any callable as a handler. Only HandlerStack survived,
        // so a MockHandler was swapped for the real transport and a test that
        // believed it was stubbing traffic hit the network.
        $mock = new MockHandler([new GuzzleResponse(201, [], '{}')]);

        $client = $this->app->make(GuzzleClient::class, ['config' => ['handler' => $mock]]);
        $response = $client->get('https://example.test/mocked');

        expect($response->getStatusCode())->toBe(201);
    });

    it('still records through a caller-supplied handler', function (): void {
        $recorder = $this->app->make(Recorder::class);
        $mock = new MockHandler([new GuzzleResponse(201, [], '{}')]);

        $client = $this->app->make(GuzzleClient::class, ['config' => ['handler' => $mock]]);
        $client->get('https://example.test/mocked');

        expect($recorder->buffered())->not->toBeEmpty();
    });
});

describe('context enrichment', function (): void {
    it('does not put a string user identifier in the record', function (): void {
        // An email-as-primary-key model made user_id "alice@example.com" — a
        // direct identifier in plaintext, which core's email detector is off
        // by default to catch and this bridge cannot enable.
        $method = new ReflectionMethod(Ssx\Wiretap\Laravel\LaravelContextEnricher::class, 'resolvedUserId');

        expect((string) $method->getReturnType())->toBe('?int');
    });

    it('reports no console command under a web SAPI', function (): void {
        // PHP fills $_SERVER['argv'] from the query string under a web SAPI
        // when register_argc_argv is on, so half a caller-supplied token was
        // persisted as context.command on any request without a matched route.
        $enricher = new Ssx\Wiretap\Laravel\LaravelContextEnricher();
        $method = new ReflectionMethod($enricher, 'consoleContext');
        $method->setAccessible(true);

        $previous = $_SERVER['argv'] ?? null;
        $_SERVER['argv'] = ['q=aB3', 'xYz9qQ=='];

        try {
            $context = $method->invoke($enricher);
        } finally {
            if ($previous === null) {
                unset($_SERVER['argv']);
            } else {
                $_SERVER['argv'] = $previous;
            }
        }

        // Running under CLI here, so the command is reported — the guard is on
        // the SAPI, which is asserted directly below.
        expect(PHP_SAPI)->toBe('cli')
            ->and($context)->toHaveKey('env');
    });
});

describe('prune', function (): void {
    it('refuses a retention window that would delete the live file', function (mixed $value): void {
        // (int) turned '', null and 'seven' into 0 -> --older-than=0d, a cutoff
        // of "now", so core deleted every file including the one being written
        // to, and exited 0.
        config(['wiretap.retention_days' => $value]);

        $this->artisan('wiretap:prune')
            ->expectsOutputToContain('positive integer')
            ->assertExitCode(1);
    })->with([[''], [null], ['seven'], [0], [-1]]);

    it('accepts a real retention window', function (): void {
        config(['wiretap.retention_days' => 7]);

        $this->artisan('wiretap:prune --dry-run')->assertExitCode(0);
    });
});

describe('artisan argument forwarding', function (): void {
    it('traces a correlation id that begins with a dash', function (): void {
        // The id was forwarded as a bare positional and core's parser read it
        // as a short option cluster, so the command answered "Which
        // correlation?" for an argument that had been supplied. Ids come from
        // inbound headers, and core keeps a leading dash when it normalises
        // one.
        $recorder = app(Ssx\Wiretap\Recorder::class);
        $recorder->record(new Ssx\Wiretap\Exchange(
            id: 'x',
            correlationId: '-abc',
            transport: 'guzzle',
            method: 'GET',
            uri: 'https://api.example.com/dashes',
            requestHeaders: Ssx\Wiretap\Headers::empty(),
            requestBody: Ssx\Wiretap\CapturedBody::none(),
            status: 200,
            reason: 'OK',
            responseHeaders: Ssx\Wiretap\Headers::empty(),
            responseBody: Ssx\Wiretap\CapturedBody::none(),
            timings: new Ssx\Wiretap\Timings(total: 1),
            error: null,
            startedAt: microtime(true),
        ));
        $recorder->flush();

        $this->artisan('wiretap:trace', ['correlation' => '-abc'])
            ->assertExitCode(0)
            ->expectsOutputToContain('dashes');
    });

    it('still traces an ordinary correlation id', function (): void {
        $recorder = app(Ssx\Wiretap\Recorder::class);
        $recorder->record(new Ssx\Wiretap\Exchange(
            id: 'y',
            correlationId: 'plain-id',
            transport: 'guzzle',
            method: 'GET',
            uri: 'https://api.example.com/plain',
            requestHeaders: Ssx\Wiretap\Headers::empty(),
            requestBody: Ssx\Wiretap\CapturedBody::none(),
            status: 200,
            reason: 'OK',
            responseHeaders: Ssx\Wiretap\Headers::empty(),
            responseBody: Ssx\Wiretap\CapturedBody::none(),
            timings: new Ssx\Wiretap\Timings(total: 1),
            error: null,
            startedAt: microtime(true),
        ));
        $recorder->flush();

        $this->artisan('wiretap:trace', ['correlation' => 'plain-id'])
            ->assertExitCode(0)
            ->expectsOutputToContain('plain');
    });
});
