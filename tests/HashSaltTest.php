<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Recorder;

/**
 * Core keeps a digest of a body it did not store (omitted, or truncated) only
 * as an HMAC under RedactionConfig::$hashSalt, and none at all without one.
 * The bridge never set that salt, so every such body lost the "did this body
 * change between calls" comparison.
 *
 * The bodies here carry the full-body SHA-256 the capture layer supplies
 * (ssx/wiretap-auto always does), and go through the redactor the provider
 * built, so what is asserted is exactly what would reach the log.
 */
function truncatedBody(): string
{
    return str_repeat('the quick brown fox jumps over the lazy dog ', 10);
}

function binaryBody(): string
{
    return "\x89PNG\r\n\x1a\n" . str_repeat("\x00\x01\x02\x03", 16);
}

/**
 * The digest kept of a truncated text body and of an omitted binary body,
 * each redacted twice.
 *
 * @return array{truncated: list<?string>, binary: list<?string>}
 */
function digestsOfTwoCalls(): array
{
    $redactor = app(Recorder::class)->redactor();
    $digests = ['truncated' => [], 'binary' => []];

    for ($i = 0; $i < 2; ++$i) {
        $truncated = $redactor->redactBody(CapturedBody::captured(
            bytes: substr(truncatedBody(), 0, 32),
            size: strlen(truncatedBody()),
            contentType: 'text/plain',
            truncated: true,
            sha256: hash('sha256', truncatedBody()),
        ));

        $binary = $redactor->redactBody(CapturedBody::captured(
            bytes: binaryBody(),
            contentType: 'image/png',
            sha256: hash('sha256', binaryBody()),
        ));

        expect($truncated->truncated)->toBeTrue()
            ->and($binary->omittedReason)->toBe(CapturedBody::OMITTED_BINARY);

        $digests['truncated'][] = $truncated->sha256;
        $digests['binary'][] = $binary->sha256;
    }

    return $digests;
}

describe('digest of a body that was not stored', function (): void {
    beforeEach(function (): void {
        $this->bootWith(['app.key' => 'base64:c2VjcmV0LWFwcC1rZXktZm9yLXRoZS1oYXNoLXNhbHQ=']);
    });

    it('keeps a stable keyed digest by default', function (): void {
        $digests = digestsOfTwoCalls();

        // Derived from app.key, not app.key itself: the sampler is already
        // keyed with app.key.
        $key = hash_hmac('sha256', 'wiretap-redaction', (string) config('app.key'));

        expect($digests['truncated'][0])->toBe(hash_hmac('sha256', hash('sha256', truncatedBody()), $key))
            ->and($digests['truncated'][1])->toBe($digests['truncated'][0])
            ->and($digests['binary'][0])->toBe(hash_hmac('sha256', hash('sha256', binaryBody()), $key))
            ->and($digests['binary'][1])->toBe($digests['binary'][0]);
    });

    it('never keeps the raw SHA-256 of the bytes it did not store', function (): void {
        $digests = digestsOfTwoCalls();

        expect($digests['truncated'][0])->not->toBe(hash('sha256', truncatedBody()))
            ->and($digests['binary'][0])->not->toBe(hash('sha256', binaryBody()));
    });
});

describe('redaction.hash_salt', function (): void {
    it('overrides the key derived from app.key', function (): void {
        $this->bootWith(['wiretap.redaction.hash_salt' => 'explicit-redaction-salt']);

        $digests = digestsOfTwoCalls();

        expect($digests['truncated'][0])
            ->toBe(hash_hmac('sha256', hash('sha256', truncatedBody()), 'explicit-redaction-salt'))
            ->and($digests['binary'][0])
            ->toBe(hash_hmac('sha256', hash('sha256', binaryBody()), 'explicit-redaction-salt'));
    });

    it('keeps no digest when set to an empty value', function (string $salt): void {
        $this->bootWith(['wiretap.redaction.hash_salt' => $salt]);

        $digests = digestsOfTwoCalls();

        expect($digests['truncated'])->toBe([null, null])
            ->and($digests['binary'])->toBe([null, null]);
    })->with(['empty' => '', 'blank' => '  ']);

    it('keeps no digest and does not throw when there is no app key', function (?string $key): void {
        $this->bootWith(['app.key' => $key]);

        $digests = digestsOfTwoCalls();

        expect($digests['truncated'])->toBe([null, null])
            ->and($digests['binary'])->toBe([null, null]);
    })->with([
        'empty' => '',
        'blank' => '   ',
        'missing' => null,
    ]);
});
