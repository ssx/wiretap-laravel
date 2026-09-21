<?php

declare(strict_types=1);

use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Redaction\RedactionConfig;
use Ssx\Wiretap\Redaction\Redactor;

/**
 * @param array<string, mixed> $redaction
 */
function redactionConfigFrom(array $redaction): RedactionConfig
{
    $provider = new WiretapServiceProvider(app());
    $method = new ReflectionMethod($provider, 'redactionConfig');
    $method->setAccessible(true);

    return $method->invoke($provider, $redaction);
}

describe('redaction options reachable from config', function (): void {
    it('adds a configured header to the defaults instead of replacing them', function (): void {
        // Only enabled, body_paths and max_body_bytes used to reach core, so
        // an application whose partner API uses X-Partner-Secret could not
        // stop that header being captured in full.
        $config = redactionConfigFrom(['headers' => ['X-Partner-Secret']]);

        expect($config->headers)->toContain('x-partner-secret')
            // Replacing would mean naming one header silently stopped
            // Authorization being removed, which is the opposite of the ask.
            ->and($config->headers)->toContain('authorization')
            ->and($config->headers)->toContain('cookie');
    });

    it('does not duplicate a header the defaults already carry', function (): void {
        $config = redactionConfigFrom(['headers' => ['Authorization']]);

        expect(array_keys($config->headers, 'authorization', true))->toHaveCount(1);
    });

    it('flips one detector without restating the others', function (): void {
        // patterns.email is off by default and could not be enabled at all,
        // which matters because a string user identifier can be an email.
        $config = redactionConfigFrom(['patterns' => ['email' => true]]);

        expect($config->patterns['email'])->toBeTrue()
            ->and($config->patterns['pan'])->toBeTrue()
            ->and($config->patterns['jwt'])->toBeTrue();
    });

    it('passes a custom pattern through to the redactor', function (): void {
        $config = redactionConfigFrom(['custom' => ['/\bacct_[A-Za-z0-9]{6}\b/']]);

        expect($config->custom)->toHaveCount(1)
            ->and((new Redactor($config))->invalidPatterns())->toBeEmpty();
    });

    it('redacts a configured header end to end', function (): void {
        $config = redactionConfigFrom(['headers' => ['X-Partner-Secret']]);

        $headers = (new Redactor($config))->redactHeaders(
            Ssx\Wiretap\Headers::fromPairs([['X-Partner-Secret', 'ordinarysecretvalue']]),
        );

        expect($headers->first('X-Partner-Secret'))->not->toContain('ordinarysecretvalue');
    });

    it('keeps core defaults when nothing is configured', function (): void {
        $config = redactionConfigFrom([]);
        $defaults = new RedactionConfig();

        expect($config->headers)->toBe($defaults->headers)
            ->and($config->query)->toBe($defaults->query)
            ->and($config->patterns)->toBe($defaults->patterns)
            ->and($config->safetyNet)->toBeTrue();
    });

    it('can turn the safety net off deliberately', function (): void {
        expect(redactionConfigFrom(['safety_net' => false])->safetyNet)->toBeFalse();
    });
});

describe('doctor', function (): void {
    it('flags a log path inside the web root', function (): void {
        // 0600 files protect against other users. The webserver runs as the
        // same user, so a path under public/ is simply downloadable.
        config(['wiretap.path' => public_path('wiretap')]);

        $this->artisan('wiretap:doctor')
            ->expectsOutputToContain('INSIDE the web root');
    });

    it('does not flag the default storage path', function (): void {
        config(['wiretap.path' => storage_path('logs/wiretap')]);

        $this->artisan('wiretap:doctor')
            ->doesntExpectOutputToContain('INSIDE the web root');
    });
});
