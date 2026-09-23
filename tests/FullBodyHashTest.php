<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Psr7\NoSeekStream;
use GuzzleHttp\Psr7\PumpStream;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Recorder;

/**
 * Core keeps a digest of a body it did not store (omitted, or truncated) only
 * as an HMAC under the redaction salt, and it can only do that when the
 * capture layer hands it the SHA-256 of the whole body. The Guzzle bridge
 * computes that only when asked to, and nothing here asked, so the salt the
 * provider derives from app.key had nothing to key: every truncated or
 * omitted body from the Http facade and the container client carried no
 * digest at all.
 */
const APP_KEY = 'base64:c2VjcmV0LWFwcC1rZXktZm9yLXRoZS1oYXNoLXNhbHQ=';

function redactionKey(): string
{
    return hash_hmac('sha256', 'wiretap-redaction', APP_KEY);
}

/** Longer than core's 64 KiB storage limit, well inside the capture budget. */
function longText(): string
{
    return str_repeat('the quick brown fox jumps over the lazy dog ', 3000);
}

function pngBytes(): string
{
    return "\x89PNG\r\n\x1a\n" . str_repeat("\x00\x01\x02\x03", 4096);
}

/**
 * @return list<Exchange>
 */
function buffered(): array
{
    return app(Recorder::class)->buffered();
}

/**
 * A stream that counts the bytes read from it, so a test can tell whether
 * hashing read anything the capture would not have read anyway.
 */
final class CountingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    public int $bytesRead = 0;

    public function __construct(private StreamInterface $stream)
    {
    }

    public function read($length): string
    {
        $chunk = $this->stream->read($length);
        $this->bytesRead += strlen($chunk);

        return $chunk;
    }
}

describe('a body core does not store in full', function (): void {
    beforeEach(function (): void {
        $this->bootWith(['app.key' => APP_KEY]);
    });

    it('keeps a keyed digest of a truncated response from the Http facade', function (): void {
        Http::fake(['api.example.com/*' => Http::response(longText(), 200, ['Content-Type' => 'text/plain'])]);

        Http::get('https://api.example.com/v1/report');

        $body = buffered()[0]->responseBody;

        expect($body->truncated)->toBeTrue()
            ->and($body->sha256)->toBe(hash_hmac('sha256', hash('sha256', longText()), redactionKey()));
    });

    it('keeps a keyed digest of a truncated request from the Http facade', function (): void {
        Http::fake(['api.example.com/*' => Http::response('', 204)]);

        Http::withBody(longText(), 'text/plain')->post('https://api.example.com/v1/upload');

        $body = buffered()[0]->requestBody;

        expect($body->truncated)->toBeTrue()
            ->and($body->sha256)->toBe(hash_hmac('sha256', hash('sha256', longText()), redactionKey()));
    });

    it('keeps a keyed digest of an omitted binary response from the container client', function (): void {
        $client = app(GuzzleClient::class, ['config' => ['handler' => static fn (): FulfilledPromise => new FulfilledPromise(
            new GuzzleResponse(200, ['Content-Type' => 'image/png'], pngBytes()),
        )]]);

        $client->get('https://cdn.example.com/logo.png');

        $body = buffered()[0]->responseBody;

        expect($body->omittedReason)->toBe(CapturedBody::OMITTED_BINARY)
            ->and($body->sha256)->toBe(hash_hmac('sha256', hash('sha256', pngBytes()), redactionKey()));
    });

    it('never stores the raw SHA-256 of what it did not store', function (): void {
        Http::fake(['api.example.com/*' => Http::response(longText(), 200, ['Content-Type' => 'text/plain'])]);

        Http::get('https://api.example.com/v1/report');

        expect(buffered()[0]->responseBody->sha256)->not->toBe(hash('sha256', longText()));
    });
});

describe('redaction.hash_full_body', function (): void {
    it('keeps no digest when switched off', function (mixed $off): void {
        $this->bootWith(['app.key' => APP_KEY, 'wiretap.redaction.hash_full_body' => $off]);

        Http::fake([
            'api.example.com/text' => Http::response(longText(), 200, ['Content-Type' => 'text/plain']),
            'api.example.com/png' => Http::response(pngBytes(), 200, ['Content-Type' => 'image/png']),
        ]);

        Http::get('https://api.example.com/text');
        Http::get('https://api.example.com/png');

        [$text, $png] = buffered();

        expect($text->responseBody->truncated)->toBeTrue()
            ->and($text->responseBody->sha256)->toBeNull()
            ->and($png->responseBody->omittedReason)->toBe(CapturedBody::OMITTED_BINARY)
            ->and($png->responseBody->sha256)->toBeNull();
    })->with(['false' => false, 'string' => 'false', 'zero' => '0', 'off' => 'off']);

    it('is forced off without a salt, whatever it says', function (array $config): void {
        $this->bootWith($config + ['wiretap.redaction.hash_full_body' => true]);

        Http::fake(['api.example.com/*' => Http::response(longText(), 200, ['Content-Type' => 'text/plain'])]);

        Http::get('https://api.example.com/v1/report');

        expect(buffered()[0]->responseBody->sha256)->toBeNull();
    })->with([
        'no app key' => [['app.key' => '']],
        'empty salt' => [['app.key' => APP_KEY, 'wiretap.redaction.hash_salt' => '']],
    ]);

    it('is forced off when redaction is off, so nothing unkeyed is written', function (): void {
        $this->bootWith([
            'app.key' => APP_KEY,
            'wiretap.redaction.enabled' => false,
            'wiretap.redaction.hash_full_body' => true,
        ]);

        Http::fake(['api.example.com/*' => Http::response(longText(), 200, ['Content-Type' => 'text/plain'])]);

        Http::get('https://api.example.com/v1/report');

        expect(buffered()[0]->responseBody->sha256)->toBeNull();
    });
});

/**
 * Hashing must never change what the application sends or reads. Each case
 * runs the same traffic with hashing on and off, through the container client,
 * and compares everything the application and the transport could observe.
 */
describe('what the application sees', function (): void {
    /**
     * @param \Closure(): StreamInterface         $requestBody
     * @param \Closure(): StreamInterface         $responseBody
     * @param array<string, mixed>                $options
     * @return array<string, mixed>
     */
    function observe(bool $hash, \Closure $requestBody, \Closure $responseBody, array $options = []): array
    {
        test()->bootWith(['app.key' => APP_KEY, 'wiretap.redaction.hash_full_body' => $hash]);

        $sent = [];
        $request = new CountingStream($requestBody());
        $response = new CountingStream($responseBody());

        $handler = static function (RequestInterface $r) use (&$sent, $response): FulfilledPromise {
            // What a transport would see: where the body stands, then what it
            // reads from there.
            $body = $r->getBody();
            $sent['position'] = $body->isSeekable() ? $body->tell() : null;
            $sent['bytes'] = hash('sha256', $body->getContents());

            return new FulfilledPromise(new GuzzleResponse(200, ['Content-Type' => 'text/plain'], $response));
        };

        $client = app(GuzzleClient::class, ['config' => ['handler' => $handler]]);
        $result = $client->post('https://api.example.com/v1/echo', $options + ['body' => $request]);

        $appBody = $result->getBody();
        $seen = [
            'position' => $appBody->isSeekable() ? $appBody->tell() : null,
            'bytes' => hash('sha256', $appBody->getContents()),
        ];

        $record = buffered()[0];

        return [
            'sent' => $sent,
            'seen' => $seen,
            // Everything read from either stream, by anyone. Equal counts mean
            // hashing read nothing the capture had not already read.
            'request read' => $request->bytesRead,
            'response read' => $response->bytesRead,
            'request omitted' => $record->requestBody->omittedReason,
            'response omitted' => $record->responseBody->omittedReason,
            'digests' => [$record->requestBody->sha256 !== null, $record->responseBody->sha256 !== null],
        ];
    }

    it('is identical with and without hashing', function (\Closure $request, \Closure $response, array $options, array $digests): void {
        $on = observe(true, $request, $response, $options);
        $off = observe(false, $request, $response, $options);

        $digestsOn = $on['digests'];
        unset($on['digests'], $off['digests']);

        expect($on)->toBe($off)
            // And the case really did what it says: hashing on produced a
            // digest where the body passed through whole, and none elsewhere.
            ->and($digestsOn)->toBe($digests)
            ->and($off)->not->toBe([]);
    })->with([
        'seekable, left mid-stream by the application' => [
            static function (): StreamInterface {
                $s = Utils::streamFor(longText());
                $s->seek(10);

                return $s;
            },
            static function (): StreamInterface {
                $s = Utils::streamFor(longText());
                $s->seek(7);

                return $s;
            },
            [],
            [true, true],
        ],
        'non-seekable' => [
            static fn (): StreamInterface => new NoSeekStream(Utils::streamFor(longText())),
            static fn (): StreamInterface => new NoSeekStream(Utils::streamFor(longText())),
            [],
            [false, false],
        ],
        'unknown length' => [
            static function (): StreamInterface {
                $data = longText();

                return new PumpStream(static function (int $n) use (&$data): string|false {
                    if ($data === '') {
                        return false;
                    }

                    $chunk = substr($data, 0, $n);
                    $data = substr($data, strlen($chunk));

                    return $chunk;
                });
            },
            static fn (): StreamInterface => Utils::streamFor(longText()),
            [],
            [false, true],
        ],
        'a streamed response' => [
            static fn (): StreamInterface => Utils::streamFor(longText()),
            static fn (): StreamInterface => Utils::streamFor(longText()),
            ['stream' => true],
            [true, false],
        ],
        'larger than the capture budget' => [
            static fn (): StreamInterface => Utils::streamFor(str_repeat('a', 3 * 1_048_576)),
            static fn (): StreamInterface => Utils::streamFor(str_repeat('b', 3 * 1_048_576)),
            [],
            [false, false],
        ],
        'exactly the capture budget' => [
            static fn (): StreamInterface => Utils::streamFor(str_repeat('a', 1_048_576)),
            static fn (): StreamInterface => Utils::streamFor(str_repeat('b', 1_048_576 - 1)),
            [],
            [false, true],
        ],
    ]);
});
