<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Recorder;

describe('a caller-supplied callable handler', function (): void {
    it('behaves exactly as it does without the container', function (bool $enabled): void {
        // HandlerStack::create() adds http_errors, redirect, cookie and
        // body-preparation middleware the callable never had, so a 404 from a
        // MockHandler became a ClientException — with capture off too.
        $this->bootWith(['wiretap.enabled' => $enabled]);

        $plain = new GuzzleClient(['handler' => new MockHandler([new GuzzleResponse(404)])]);
        $resolved = $this->app->make(GuzzleClient::class, ['config' => [
            'handler' => new MockHandler([new GuzzleResponse(404)]),
        ]]);

        expect($plain->get('https://example.test/missing')->getStatusCode())->toBe(404)
            ->and($resolved->get('https://example.test/missing')->getStatusCode())->toBe(404);

        if ($enabled) {
            // And the record says what the application saw.
            $record = $this->app->make(Recorder::class)->buffered()[0];

            expect($record->status)->toBe(404)
                ->and($record->error)->toBeNull();
        }
    })->with([[true], [false]]);

    it('does not follow a redirect the callable would have returned', function (): void {
        $mock = new MockHandler([
            new GuzzleResponse(302, ['Location' => 'https://example.test/elsewhere']),
            new GuzzleResponse(200),
        ]);

        $client = $this->app->make(GuzzleClient::class, ['config' => ['handler' => $mock]]);

        expect($client->get('https://example.test/start')->getStatusCode())->toBe(302)
            ->and($mock->count())->toBe(1);
    });
});

describe('a malformed blocklist', function (): void {
    it('does not stop the application booting', function (bool $enabled): void {
        // Validation threw while the recorder was being built, outside core's
        // fail-closed handling, so boot() could not resolve it and the whole
        // application went down — with capture off as well.
        $this->bootWith(['wiretap.enabled' => $enabled, 'wiretap.blocklist' => ['ok.test', 42]]);

        expect($this->app->make(Recorder::class))->toBeInstanceOf(Recorder::class);
    })->with([[true], [false]]);

    it('warns in the application log once per process, and only with capture on', function (): void {
        // The recorder is built on every request, so a warning per build
        // flooded any channel that pages someone.
        $warned = new ReflectionProperty(WiretapServiceProvider::class, 'warned');
        $warnings = [];

        $capture = function (bool $enabled, int $builds) use (&$warnings, $warned): void {
            $this->bootWith(['wiretap.enabled' => $enabled, 'wiretap.blocklist' => ['ok.test', 42]]);
            // Booting already built the recorder with the real logger.
            $warned->setValue(null, []);

            $log = Mockery::mock();
            $log->shouldReceive('warning')->andReturnUsing(function (string $message) use (&$warnings): void {
                $warnings[] = $message;
            });
            $this->app->instance('log', $log);

            for ($i = 0; $i < $builds; $i++) {
                $this->app->forgetInstance(Recorder::class);
                $this->app->make(Recorder::class);
            }
        };

        $capture(false, 1);
        expect($warnings)->toBe([]);

        $capture(true, 3);

        expect($warnings)->toHaveCount(1)
            ->and($warnings[0])->toContain('wiretap.blocklist entries must be strings');
    });

    it('fails a malformed preset closed too, without breaking doctor', function (): void {
        // Core's error path calls the provider's name(), which implodes the
        // presets: an object raised an error from inside core's catch.
        $this->bootWith(['wiretap.presets' => [new stdClass()]]);

        $blocklist = $this->app->make(Recorder::class)->blocklist();

        expect($blocklist->hasFailedClosed())->toBeTrue()
            ->and(implode("\n", $blocklist->errors()))->toContain('wiretap.presets entries must be strings');

        Artisan::call('wiretap:doctor');
    });

    it('reads a comma-separated blocklist string as rules, not as one host', function (): void {
        // `'blocklist' => env('X')` gave one literal entry: every rule in it
        // silently absent.
        $this->bootWith(['wiretap.blocklist' => 'pay.test,*.acquirer.test']);

        $blocklist = $this->app->make(Recorder::class)->blocklist();

        expect($blocklist->blocks('https://pay.test/x'))->toBeTrue()
            ->and($blocklist->blocks('https://a.acquirer.test/x'))->toBeTrue();
    });

    it('blocks all capture until it is corrected, and says why', function (): void {
        $this->bootWith(['wiretap.blocklist' => ['ok.test', 42]]);

        Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
        Http::get('https://unrelated.example.test/call');

        $blocklist = $this->app->make(Recorder::class)->blocklist();

        expect($this->app->make(Recorder::class)->buffered())->toBe([])
            ->and($blocklist->hasFailedClosed())->toBeTrue()
            ->and(implode("\n", $blocklist->errors()))->toContain('wiretap.blocklist entries must be strings');
    });
});
