<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Support\Facades\Http;
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

    it('warns in the application log', function (): void {
        $this->bootWith(['wiretap.blocklist' => ['ok.test', 42]]);

        $warnings = [];
        $log = Mockery::mock();
        $log->shouldReceive('warning')->andReturnUsing(function (string $message) use (&$warnings): void {
            $warnings[] = $message;
        });
        $this->app->instance('log', $log);
        $this->app->forgetInstance(Recorder::class);

        $this->app->make(Recorder::class);

        expect(implode("\n", $warnings))->toContain('wiretap.blocklist entries must be strings');
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
