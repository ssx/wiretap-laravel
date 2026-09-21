# wiretap-laravel

Laravel integration for [wiretap](https://github.com/ssx/wiretap). Captures
outbound HTTP requests and responses, tags each with the route or command that
caused it, and groups every call from one inbound request under a single
correlation id.

```bash
composer require ssx/wiretap-laravel
php artisan vendor:publish --tag=wiretap-config
```

Then, only when you need it:

```dotenv
WIRETAP_ENABLED=true
```

Nothing is recorded until you set that. A package that began recording personal
data the moment it was installed would be indefensible.

## What it captures

| Surface | Covered |
| --- | --- |
| `Http::get()`, `Http::post()` — Laravel's HTTP client | yes |
| Guzzle resolved from the container | yes |
| `new GuzzleHttp\Client()` inside your vendor directory | **no** |
| raw `curl_exec()` anywhere | **no** |

The last two need [`ssx/wiretap-auto`](https://github.com/ssx/wiretap-auto),
which hooks the functions themselves. `php artisan wiretap:doctor` will tell
you which of these are live.

## It does not break `Http::fake()`

Capture is attached with `Http::globalMiddleware()`, which pushes onto the
handler stack. It is deliberately **not** `Http::globalOptions(['handler' =>
...])` — that replaces the handler, including the one `Http::fake()` installs,
which would silently break every faked HTTP test in your suite.

Installing an observability package must not change how your tests behave.

## Commands

```bash
php artisan wiretap:list --host=api.example.com --failed
php artisan wiretap:show 1 --curl
php artisan wiretap:trace <correlation-id>
php artisan wiretap:export --failed --out=failures.har
php artisan wiretap:prune --older-than=7d
php artisan wiretap:doctor
```

`wiretap:export` writes HAR 1.2, which Chrome DevTools, Proxyman, Charles,
Insomnia and Postman all import.

Schedule the prune. Captured payloads are personal data and Article 5(1)(e)
storage limitation applies to them, so retention is an obligation rather than
housekeeping:

```php
$schedule->command('wiretap:prune')->daily();
```

## Correlation and context

A middleware seeds the correlation id from an inbound `traceparent`,
`X-Request-Id` or `X-Correlation-Id`, so a trace joins up with whatever called
you. Every outbound call made while handling that request shares the id, and
`wiretap:trace` renders the lot as a waterfall.

Each exchange is tagged with the route name, action, path and — where one is
already resolved — the user id. Resolving the user is deliberately not forced:
doing so would trigger a session and a database query on routes that need
neither.

## Testing

```php
use Ssx\Wiretap\Wiretap;

Wiretap::fake();

$this->post('/checkout');

Wiretap::assertSent('api.example.com', times: 2);
Wiretap::assertNothingSentTo('api.stripe.com');
```

Works alongside `Http::fake()`. The capture layer resolves its recorder per
call, so calling `Wiretap::fake()` inside a test redirects traffic that was
wired up at boot.

## Configuration

`config/wiretap.php` covers the blocklist, redaction body paths, sampling,
capture surfaces, storage path and retention. Every value is annotated.

The two worth setting for your project:

```php
'blocklist' => array_merge(
    // Keep this. Once the config is cached Laravel stops loading .env, so
    // without it WIRETAP_BLOCK becomes a no-op in exactly the deployments
    // most likely to have capture switched on.
    EnvBlocklistProvider::parse((string) env('WIRETAP_BLOCK', '')),
    ['*.myacquirer.test'],                     // never recorded at all
),

'redaction' => [
    'body_paths' => ['card.cvv'],              // recorded, but redacted
    'headers' => ['X-Partner-Secret'],         // added to the defaults, not replacing them
],
```

Editing the published config replaces the array it appears in, which is why
the `array_merge` above matters — writing `'blocklist' => ['*.myacquirer.test']`
on its own silently drops the env blocklist.

Wiretap cannot know which of your endpoints carry cardholder data or which
keys in your payloads are sensitive. You do.

## Requirements

PHP 8.2+, Laravel 11 or 12.

Laravel 10 is not supported: `Http::globalMiddleware()` arrived in 11, and the
alternative would mean either breaking `Http::fake()` or shipping a degraded
capture tier. Laravel 10 reached end of life in February 2025.

## ⚠️ Do not leave it running

Wiretap records complete request and response bodies. It is not PCI-DSS
compliant and not GDPR compliant on its own. See the
[main README](https://github.com/ssx/wiretap).

## Licence

MIT.
