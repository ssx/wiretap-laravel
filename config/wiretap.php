<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\PresetBlocklistProvider;

return [

    /*
    |--------------------------------------------------------------------------
    | Enabled
    |--------------------------------------------------------------------------
    |
    | Wiretap is a debugging tool, not a logging product. It records complete
    | request and response bodies, which routinely contain personal data and
    | on a commerce site can contain cardholder data.
    |
    | Turn it on to investigate something, then turn it off again. It defaults
    | to off outside local for exactly that reason.
    |
    */

    'enabled' => env('WIRETAP_ENABLED', false),

    /*
    |--------------------------------------------------------------------------
    | Blocklist
    |--------------------------------------------------------------------------
    |
    | A URL matching any of these produces no record at all — the body is never
    | read, the headers are never copied, nothing enters the buffer. It is a
    | gate, not a filter. Use it for anything carrying cardholder data.
    |
    |   api.stripe.com                exact host, any scheme or path
    |   *.adyen.com                   the host and any subdomain
    |   api.foo.com/v2/payments*      host plus path prefix
    |   ~^https://api\.foo\.com/v2/~  full-URL regex, tilde-delimited
    |
    */

    'presets' => [
        PresetBlocklistProvider::PAYMENT_GATEWAYS,
        PresetBlocklistProvider::CLOUD_METADATA,
    ],

    'blocklist' => array_filter(array_map('trim', explode(',', (string) env('WIRETAP_BLOCK', '')))) + [
        // 'internal-billing.example.com',
        // '*.myacquirer.test',
    ],

    /*
    |--------------------------------------------------------------------------
    | Redaction
    |--------------------------------------------------------------------------
    |
    | Applied at capture, never at display. Body paths use dot notation with
    | `*` wildcards over decoded JSON, so they are precise in a way a regex
    | over raw text cannot be.
    |
    | Wiretap cannot know which keys in your payloads are sensitive. Headers,
    | query parameters and card numbers are handled by default; the paths below
    | are yours.
    |
    */

    'redaction' => [
        'enabled' => env('WIRETAP_REDACT', true),

        'body_paths' => [
            // 'card.number',
            // 'card.cvv',
            // '*.password',
            // 'customer.email',
        ],

        'max_body_bytes' => env('WIRETAP_BODY_LIMIT', 65536),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sampling
    |--------------------------------------------------------------------------
    |
    | Deterministic on the correlation id, so every outbound call made while
    | handling one inbound request shares the same decision. Sampling per call
    | would give you half a conversation.
    |
    | 10000 basis points keeps everything. In production you would drop this
    | and lean on the always-keep rules below.
    |
    */

    'sample_rate_basis_points' => env('WIRETAP_SAMPLE_BP', 10000),
    'always_keep_failures' => true,
    'slow_threshold_us' => env('WIRETAP_SLOW_US', 2_000_000),

    /*
    |--------------------------------------------------------------------------
    | Capture surfaces
    |--------------------------------------------------------------------------
    |
    | `http_client` reaches Laravel's own HTTP client. `container_guzzle` binds
    | a recorded Guzzle client for anything resolving one from the container.
    |
    | Neither reaches a `new GuzzleHttp\Client()` inside your vendor directory,
    | and neither sees raw curl_exec() at all. Install ssx/wiretap-auto for
    | those.
    |
    */

    'capture' => [
        'http_client' => true,
        'container_guzzle' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    */

    'path' => env('WIRETAP_PATH', storage_path('logs/wiretap')),

    'retention_days' => env('WIRETAP_RETENTION_DAYS', 7),

];
