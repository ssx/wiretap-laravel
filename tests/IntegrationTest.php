<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Ssx\Wiretap\Correlation;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Query\ExchangeQuery;
use Ssx\Wiretap\Wiretap;

function recorded(string $path): array
{
    app(Recorder::class)->flush();

    return iterator_to_array((new NdjsonReader($path))->query(new ExchangeQuery(limit: 50)), false);
}

describe('wiring', function (): void {
    it('registers the recorder as a singleton', function (): void {
        expect(app(Recorder::class))->toBe(app(Recorder::class))
            ->and(app(Recorder::class)->isEnabled())->toBeTrue();
    });

    it('shares its recorder with the global holder, so the curl hooks agree', function (): void {
        // Two holders would mean the hooks write somewhere the application
        // never configured. There must be exactly one.
        expect(Wiretap::recorder())->toBe(app(Recorder::class));
    });

    it('publishes its config', function (): void {
        expect(config('wiretap.enabled'))->toBeTrue()
            ->and(config('wiretap.redaction.enabled'))->toBeTrue();
    });
});

describe('capture surfaces', function (): void {
    it('captures the Http facade with no application changes', function (): void {
        Http::fake(['api.example.com/*' => Http::response(['id' => 42], 201)]);

        Http::post('https://api.example.com/v1/orders', ['sku' => 'ABC']);

        $exchanges = recorded($this->logPath);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->method)->toBe('POST')
            ->and($exchanges[0]->status)->toBe(201);
    });

    it('captures a Guzzle client resolved from the container', function (): void {
        $client = app(GuzzleClient::class);

        // The client is recorded; the request itself will fail to connect,
        // which is fine — a transport failure is still an exchange.
        try {
            $client->get('http://127.0.0.1:1/nothing', ['timeout' => 1]);
        } catch (\Throwable) {
        }

        expect(recorded($this->logPath))->toHaveCount(1);
    });

    it('does not capture when disabled', function (): void {
        $this->bootWith(['wiretap.enabled' => false]);

        Http::fake(['api.example.com/*' => Http::response([], 200)]);
        Http::get('https://api.example.com/v1');

        expect(recorded($this->logPath))->toBeEmpty();
    });
});

describe('redaction and blocklist through the container', function (): void {
    it('applies configured body paths', function (): void {
        $this->bootWith(['wiretap.redaction.body_paths' => ['card.cvv']]);

        Http::fake(['api.example.com/*' => Http::response([], 200)]);
        Http::post('https://api.example.com/v1/pay', [
            'card' => ['cvv' => '123', 'brand' => 'visa'],
        ]);

        $written = json_encode(recorded($this->logPath));

        expect($written)->not->toContain('"123"')
            ->and($written)->toContain('visa');
    });

    it('drops a blocklisted host entirely', function (): void {
        $this->bootWith(['wiretap.blocklist' => ['*.stripe.com']]);

        Http::fake(['api.stripe.com/*' => Http::response(['charged' => true], 200)]);
        $response = Http::post('https://api.stripe.com/v1/charges');

        // Blocking capture must never block traffic.
        expect($response->status())->toBe(200)
            ->and(recorded($this->logPath))->toBeEmpty();
    });
});

describe('context and correlation', function (): void {
    it('tags an exchange with the route that caused it', function (): void {
        Route::get('/orders', function () {
            Http::get('https://api.example.com/v1/orders');

            return 'ok';
        })->name('orders.index');

        Http::fake(['api.example.com/*' => Http::response([], 200)]);

        $this->get('/orders')->assertOk();

        $exchanges = recorded($this->logPath);

        expect($exchanges)->toHaveCount(1)
            ->and($exchanges[0]->context['route'] ?? null)->toBe('orders.index')
            ->and($exchanges[0]->context['uri'] ?? null)->toBe('/orders');
    });

    it('adopts the trace id from an inbound traceparent', function (): void {
        Route::get('/ping', function () {
            Http::get('https://api.example.com/v1/ping');

            return 'ok';
        });

        Http::fake(['api.example.com/*' => Http::response([], 200)]);

        $this->withHeaders([
            'traceparent' => '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        ])->get('/ping')->assertOk();

        $exchanges = recorded($this->logPath);

        expect($exchanges[0]->correlationId)->toBe('4bf92f3577b34da6a3ce929d0e0e4736');
    });

    it('groups every call from one request under one correlation id', function (): void {
        Route::get('/multi', function () {
            Http::get('https://api.example.com/one');
            Http::get('https://api.example.com/two');
            Http::get('https://api.example.com/three');

            return 'ok';
        });

        Http::fake(['api.example.com/*' => Http::response([], 200)]);

        $this->get('/multi')->assertOk();

        $exchanges = recorded($this->logPath);
        $ids = array_unique(array_map(static fn ($e) => $e->correlationId, $exchanges));

        expect($exchanges)->toHaveCount(3)
            ->and($ids)->toHaveCount(1);
    });
});

describe('artisan commands', function (): void {
    it('registers all six', function (string $command): void {
        expect(array_keys(app('Illuminate\Contracts\Console\Kernel')->all()))
            ->toContain($command);
    })->with([
        'wiretap:list',
        'wiretap:show',
        'wiretap:trace',
        'wiretap:export',
        'wiretap:prune',
        'wiretap:doctor',
    ]);

    it('runs list without error when there is nothing recorded', function (): void {
        $this->artisan('wiretap:list')->assertSuccessful();
    });

    it('runs prune with the configured retention window', function (): void {
        $this->artisan('wiretap:prune', ['--dry-run' => true])->assertSuccessful();
    });
});

describe('the test API', function (): void {
    it('works inside a Laravel test', function (): void {
        Wiretap::fake();

        Http::fake(['api.example.com/*' => Http::response([], 200)]);
        Http::get('https://api.example.com/v1/orders');

        Wiretap::assertSent('api.example.com');
        Wiretap::assertNothingSentTo('api.stripe.com');

        expect(Wiretap::recorded())->toHaveCount(1);
    });
});

describe('the context enricher', function (): void {
    it('reports request context under a test runner, which is itself a console process', function (): void {
        // runningInConsole() is true here, and in a queue worker. Routing the
        // enricher on it would report a console command for a request being
        // handled. The presence of a matched route is the real signal.
        Route::get('/enriched', function () {
            Http::get('https://api.example.com/v1');

            return 'ok';
        })->name('enriched');

        Http::fake(['api.example.com/*' => Http::response([], 200)]);

        $this->get('/enriched')->assertOk();

        $context = recorded($this->logPath)[0]->context;

        expect($context['route'] ?? null)->toBe('enriched')
            ->and($context)->not->toHaveKey('command');
    });

    it('falls back to console context when no route matched', function (): void {
        $this->artisan('wiretap:list')->assertSuccessful();

        Http::fake(['api.example.com/*' => Http::response([], 200)]);
        Http::get('https://api.example.com/v1');

        $context = recorded($this->logPath)[0]->context;

        // `command` depends on argv, which a bare test run does not always
        // have. The contract being pinned is that no route is claimed when
        // none was matched.
        expect($context)->not->toHaveKey('route')
            ->and($context)->not->toHaveKey('action')
            ->and($context['env'] ?? null)->toBe('testing');
    });
});

describe('hardening found by review', function (): void {
    it('does not replace an application Guzzle client that is already bound', function (): void {
        // An unconditional bind replaced the application's own client —
        // base_uri, auth, timeouts, even a test mock handler — with a bare
        // default. That breaks production requests and sends test suites to
        // the network.
        $this->app->bind(GuzzleClient::class, static fn (): GuzzleClient => new GuzzleClient([
            'base_uri' => 'https://configured.example.com',
            'timeout' => 42,
        ]));

        $this->app->register(\Ssx\Wiretap\Laravel\WiretapServiceProvider::class, true);

        $client = app(GuzzleClient::class);

        expect((string) $client->getConfig('base_uri'))->toBe('https://configured.example.com')
            ->and($client->getConfig('timeout'))->toBe(42);
    });

    it('records the route template rather than the concrete path', function (): void {
        // /reset-password/<token> is a credential. No body-path rule can
        // protect something recorded in context.
        Route::get('/reset-password/{token}', function () {
            Http::get('https://api.example.com/v1/verify');

            return 'ok';
        })->name('password.reset');

        Http::fake(['api.example.com/*' => Http::response([], 200)]);

        $this->get('/reset-password/SUPERSECRETVALUE')->assertOk();

        $context = recorded($this->logPath)[0]->context;

        expect($context['uri'] ?? '')->toBe('/reset-password/{token}')
            ->and(json_encode($context))->not->toContain('SUPERSECRETVALUE');
    });

    it('publishes its recorder even when capture is disabled', function (): void {
        // Returning early left whatever a previous application put on the
        // holder. In a worker running several applications, an enabled
        // recorder from an earlier one kept receiving traffic.
        $this->bootWith(['wiretap.enabled' => false]);

        expect(Wiretap::recorder())->toBe(app(Recorder::class))
            ->and(Wiretap::recorder()->isEnabled())->toBeFalse();
    });

    it('keeps an env blocklist entry after config caching', function (): void {
        // EnvBlocklistProvider reads getenv() at runtime, but a cached config
        // means later processes never load .env — so the rule vanished while
        // capture stayed on.
        putenv('WIRETAP_BLOCK=private.example.com');

        try {
            $config = require __DIR__ . '/../config/wiretap.php';

            expect($config['blocklist'])->toContain('private.example.com');
        } finally {
            putenv('WIRETAP_BLOCK');
        }
    });
});

describe('resource fixes found by review', function (): void {
    it('gives each queued job its own correlation', function (): void {
        // A persistent worker never reaches the HTTP middleware, so every job
        // it handled shared one id and an ever-growing sequence — and sampling
        // is deterministic on that id, so the worker's jobs were sampled as a
        // single unit.
        $listener = app(\Ssx\Wiretap\Laravel\Queue\StartJobCorrelation::class);

        $job = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $job->shouldReceive('uuid')->andReturn(null);

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $job));
        $first = \Ssx\Wiretap\Correlation::id();
        \Ssx\Wiretap\Correlation::nextSequence();
        \Ssx\Wiretap\Correlation::nextSequence();
        $listener->processed(new \Illuminate\Queue\Events\JobProcessed('sync', $job));

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $job));
        $second = \Ssx\Wiretap\Correlation::id();

        expect($second)->not->toBe($first)
            ->and(\Ssx\Wiretap\Correlation::nextSequence())->toBe(0);
    });

    it('keeps the outer correlation for a nested synchronous job', function (): void {
        // Two distinct job objects: ownership is tracked per job, so reusing
        // one mock would not exercise nesting at all.
        $listener = app(\Ssx\Wiretap\Laravel\Queue\StartJobCorrelation::class);
        \Ssx\Wiretap\Correlation::reset();

        $outerJob = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $outerJob->shouldReceive('uuid')->andReturn('outer-uuid');
        $innerJob = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $innerJob->shouldReceive('uuid')->andReturn('inner-uuid');

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $outerJob));
        $outer = \Ssx\Wiretap\Correlation::id();

        // A job dispatched inside another is part of the same operation.
        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $innerJob));

        expect(\Ssx\Wiretap\Correlation::id())->toBe($outer);

        // The sync queue fires both of these for the same attempt. Unwinding
        // twice used to reset the *outer* job's scope out from under it.
        $listener->exceptionOccurred(new \Illuminate\Queue\Events\JobExceptionOccurred('sync', $innerJob, new RuntimeException('inner failed')));
        $listener->failed(new \Illuminate\Queue\Events\JobFailed('sync', $innerJob, new RuntimeException('inner failed')));

        expect(\Ssx\Wiretap\Correlation::id())->toBe($outer);

        $listener->processed(new \Illuminate\Queue\Events\JobProcessed('sync', $outerJob));
    });

    it('sends artisan output through Laravel so it can be buffered', function (): void {
        // Writing to STDOUT meant Artisan::call() returned an empty output()
        // and console assertions could not see anything.
        Artisan::call('wiretap:list');

        expect(Artisan::output())->toContain('No exchanges found');
    });

    it('lets the test API work when capture is disabled', function (): void {
        // Skipping surface installation meant fake() replaced the recorder and
        // then had nothing to record through, so assertSent() failed on
        // traffic that had definitely happened.
        $this->bootWith(['wiretap.enabled' => false]);

        Wiretap::fake();

        Http::fake(['api.example.com/*' => Http::response([], 200)]);
        Http::get('https://api.example.com/v1/orders');

        Wiretap::assertSent('api.example.com');

        expect(Wiretap::recorded())->toHaveCount(1);
    });
});

describe('second review round', function (): void {
    it('keeps explicit blocklist entries alongside environment ones', function (): void {
        // `+` preserves numeric keys from the left array rather than appending,
        // so an env rule at index 0 silently deleted the user's own rule at
        // index 0 — and that host's traffic was then recorded.
        putenv('WIRETAP_BLOCK=env.example');

        try {
            $config = require __DIR__ . '/../config/wiretap.php';
            $merged = array_merge($config['blocklist'], ['private.example']);

            expect($merged)->toContain('env.example')
                ->and($merged)->toContain('private.example');
        } finally {
            putenv('WIRETAP_BLOCK');
        }
    });

    it('keeps a regex quantifier intact through config caching', function (): void {
        // explode(',') split ~...[0-9]{1,3}$~ into two invalid rules, and once
        // config is cached .env is not loaded so the runtime provider cannot
        // compensate.
        putenv('WIRETAP_BLOCK=~^https://p[.]test/pay/[0-9]{1,3}$~');

        try {
            $config = require __DIR__ . '/../config/wiretap.php';

            expect($config['blocklist'])->toHaveCount(1);

            $blocklist = new \Ssx\Wiretap\Blocklist\Blocklist([
                new \Ssx\Wiretap\Blocklist\ArrayBlocklistProvider($config['blocklist']),
            ]);

            expect($blocklist->errors())->toBeEmpty()
                ->and($blocklist->blocks('https://p.test/pay/12'))->toBeTrue();
        } finally {
            putenv('WIRETAP_BLOCK');
        }
    });

    it('does not let console formatting eat an exported payload', function (): void {
        // Symfony's write() interprets console tags, so a HAR body containing
        // <info>x</info> was replayed as plain "x".
        $sink = app(Recorder::class);
        $sink->record(exchangeWithTaggedBody());
        $sink->flush();

        Artisan::call('wiretap:export');

        expect(Artisan::output())->toContain('<info>');
    });

    it('balances correlation depth when a job throws with retries remaining', function (): void {
        // JobExceptionOccurred fires alone in that case. Listening only to
        // JobProcessed/JobFailed left depth at 1 forever, so every later job
        // inherited the failed attempt's correlation.
        $listener = app(\Ssx\Wiretap\Laravel\Queue\StartJobCorrelation::class);
        \Ssx\Wiretap\Correlation::reset();

        $job = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $job->shouldReceive('uuid')->andReturn(null);

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $job));
        $first = \Ssx\Wiretap\Correlation::id();
        $listener->exceptionOccurred(new \Illuminate\Queue\Events\JobExceptionOccurred('sync', $job, new RuntimeException('retry me')));

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $job));

        expect(\Ssx\Wiretap\Correlation::id())->not->toBe($first);
    });

    it('does not take over an enclosing http correlation', function (): void {
        // A sync job dispatched inside a request is part of that request.
        // Replacing its correlation broke request-wide sampling.
        \Ssx\Wiretap\Correlation::start('inbound-request');

        $listener = app(\Ssx\Wiretap\Laravel\Queue\StartJobCorrelation::class);
        $job = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $job->shouldReceive('uuid')->andReturn('job-uuid');

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('sync', $job));

        expect(\Ssx\Wiretap\Correlation::id())->toBe('inbound-request');

        $listener->processed(new \Illuminate\Queue\Events\JobProcessed('sync', $job));

        // Still the request's, not reset out from under it.
        expect(\Ssx\Wiretap\Correlation::id())->toBe('inbound-request');
    });
});

function exchangeWithTaggedBody(): \Ssx\Wiretap\Exchange
{
    return new \Ssx\Wiretap\Exchange(
        id: 'tagged', correlationId: 'c', transport: 'curl', method: 'GET',
        uri: 'https://api.example.com/v1',
        requestHeaders: \Ssx\Wiretap\Headers::empty(),
        requestBody: \Ssx\Wiretap\CapturedBody::captured('{"note":"<info>literal</info>"}', contentType: 'application/json'),
        status: 200, reason: 'OK',
        responseHeaders: \Ssx\Wiretap\Headers::empty(),
        responseBody: \Ssx\Wiretap\CapturedBody::none(),
        timings: new \Ssx\Wiretap\Timings(total: 1000), error: null, startedAt: microtime(true),
    );
}

describe('fable review findings', function (): void {
    it('treats WIRETAP_ENABLED=off as off', function (): void {
        // Laravel's env() only converts the literal strings true/false/null,
        // so 'off' arrived as a string and (bool) 'off' is true. Capture ran,
        // writing full bodies to disk, while the operator believed it was off
        // — and core's doctor, which uses filter_var, agreed with them.
        foreach (['off', 'no', 'disabled', 'false', '0', 'nonsense'] as $value) {
            $this->bootWith(['wiretap.enabled' => $value]);

            expect(app(Recorder::class)->isEnabled())
                ->toBeFalse("WIRETAP_ENABLED={$value} should mean off");
        }
    });

    it('still treats the affirmative spellings as on', function (): void {
        foreach (['true', '1', 'yes', 'on'] as $value) {
            $this->bootWith(['wiretap.enabled' => $value]);

            expect(app(Recorder::class)->isEnabled())->toBeTrue();
        }
    });

    it('honours make() parameters on the Guzzle binding', function (): void {
        // The closure discarded $parameters, so app(Client::class, ['config' =>
        // [...]]) silently lost base_uri, auth and timeouts.
        $client = app()->makeWith(GuzzleClient::class, ['config' => [
            'base_uri' => 'https://configured.example.com',
            'timeout' => 42,
        ]]);

        expect((string) $client->getConfig('base_uri'))->toBe('https://configured.example.com')
            ->and($client->getConfig('timeout'))->toBe(42);
    });

    it('does not let a generated correlation silence every job in a worker', function (): void {
        // hasStarted() becomes true as soon as the capture middleware calls
        // id() on the first outbound call, so one HTTP call at boot meant no
        // job ever took ownership again.
        \Ssx\Wiretap\Correlation::reset();
        \Ssx\Wiretap\Correlation::id(); // generated on demand, not owned

        $listener = app(\Ssx\Wiretap\Laravel\Queue\StartJobCorrelation::class);

        $first = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $first->shouldReceive('uuid')->andReturn('job-one');
        $second = Mockery::mock(\Illuminate\Contracts\Queue\Job::class);
        $second->shouldReceive('uuid')->andReturn('job-two');

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('redis', $first));
        $a = \Ssx\Wiretap\Correlation::id();
        $listener->processed(new \Illuminate\Queue\Events\JobProcessed('redis', $first));

        $listener->processing(new \Illuminate\Queue\Events\JobProcessing('redis', $second));
        $b = \Ssx\Wiretap\Correlation::id();

        expect($a)->toBe('job-one')
            ->and($b)->toBe('job-two');
    });
});
