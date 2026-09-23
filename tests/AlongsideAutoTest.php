<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Support\Facades\Http;
use Ssx\Wiretap\Reader\NdjsonReader;
use Ssx\Wiretap\Recorder;
use Ssx\Wiretap\Query\ExchangeQuery;

/**
 * This package and ssx/wiretap-auto's curl hooks in one process, both writing
 * to the container's recorder: a real request must be recorded once, by the
 * Guzzle bridge, never again by the hooks underneath it.
 */
const ALONGSIDE_PORT = 18795;

beforeAll(function (): void {
    if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
        return;
    }

    $docroot = sys_get_temp_dir() . '/wiretap-laravel-alongside';
    @mkdir($docroot, 0o755, true);
    file_put_contents($docroot . '/index.php', <<<'ROUTER'
<?php
if (str_starts_with($_SERVER['REQUEST_URI'], '/redirect')) {
    header('Location: /echo?from=redirect', true, 302);
    exit;
}
header('Content-Type: application/json');
echo json_encode(['path' => $_SERVER['REQUEST_URI']]);
ROUTER);

    $server = proc_open(
        sprintf('exec %s -S 127.0.0.1:%d -t %s', PHP_BINARY, ALONGSIDE_PORT, escapeshellarg($docroot)),
        [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes,
    );

    for ($i = 0; $i < 50; ++$i) {
        $socket = @fsockopen('127.0.0.1', ALONGSIDE_PORT, $errno, $errstr, 0.1);

        if ($socket !== false) {
            fclose($socket);

            break;
        }

        usleep(100_000);
    }

    register_shutdown_function(static function () use ($server): void {
        proc_terminate($server);
        proc_close($server);
    });
});

beforeEach(function (): void {
    if (!extension_loaded('opentelemetry') || !class_exists(\Ssx\Wiretap\Auto\Wiretap::class)) {
        $this->markTestSkipped('needs ext-opentelemetry and ssx/wiretap-auto');
    }

    // The package boots itself from its autoload file; this only makes sure.
    \Ssx\Wiretap\Auto\Wiretap::boot();
    $this->base = 'http://127.0.0.1:' . ALONGSIDE_PORT;
});

/**
 * @return list<string> the transport of every stored record
 */
function storedTransports(string $path): array
{
    app(Recorder::class)->flush();

    return array_map(
        static fn ($e): string => $e->transport,
        iterator_to_array((new NdjsonReader($path))->query(new ExchangeQuery(limit: 50)), false),
    );
}

it('records an Http facade call once, as the bridge', function (): void {
    Http::get($this->base . '/echo?facade=1');

    expect(storedTransports($this->logPath))->toBe(['guzzle']);
});

it('records a container Guzzle client call once, redirect included', function (): void {
    app(GuzzleClient::class)->get($this->base . '/redirect');

    expect(storedTransports($this->logPath))->toBe(['guzzle']);
});

it('records a Guzzle client the application built itself once, as the hooks', function (): void {
    // Not wired to the bridge, so nothing claims it: the hooks are the only
    // layer that sees it, and they record it.
    (new GuzzleClient(['handler' => \GuzzleHttp\HandlerStack::create()]))->get($this->base . '/echo?plain=1');

    expect(storedTransports($this->logPath))->toBe(['curl']);
});
