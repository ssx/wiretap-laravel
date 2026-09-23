<?php

declare(strict_types=1);

use Ssx\Wiretap\Blocklist\EnvBlocklistProvider;
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

    'blocklist' => array_merge(
        // Parsed with the core tokenizer, not explode(',').
        //
        // A comma is legal inside a regex quantifier, so splitting on every
        // one turned ~...[0-9]{1,3}$~ into two invalid rules. And once the
        // config is cached Laravel stops loading .env, so the runtime provider
        // cannot make up the difference — the rule simply vanishes in exactly
        // the deployments most likely to have capture switched on.
        EnvBlocklistProvider::parse((string) env('WIRETAP_BLOCK', '')),
        [
            // 'internal-billing.example.com',
            // '*.myacquirer.test',
        ],
    ),

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

        /*
        | Everything below is added to what core already redacts, not
        | substituted for it. Naming one extra sensitive header should not
        | silently stop Authorization and Cookie being removed.
        */

        // Extra header names to remove, on top of Authorization, Cookie,
        // Set-Cookie, X-Api-Key and the rest.
        'headers' => [
            // 'X-Partner-Secret',
        ],

        // Extra query parameter names, on top of api_key, token, signature...
        'query' => [
            // 'session',
        ],

        // 'deny' removes the named headers. 'allow' keeps only them, which is
        // stricter and much more likely to omit something you wanted.
        'header_mode' => env('WIRETAP_HEADER_MODE', 'deny'),

        // Built-in detectors. Turning one off does not drop those values into
        // the record wholesale — the safety net respects this same set, so a
        // disabled detector is genuinely disabled rather than making things
        // worse. `email` is off by default because it false-positives on
        // ordinary prose.
        'patterns' => [
            // 'email' => true,
        ],

        // Extra regexes, applied as-is to header values and bodies.
        'custom' => [
            // '/\bacct_[A-Za-z0-9]{16}\b/',
        ],

        // The last line of defence: re-run the enabled detectors over the
        // finished record and drop the body entirely on a hit. Leave it on.
        'safety_net' => env('WIRETAP_SAFETY_NET', true),

        // A body the structured rules could not parse is omitted rather than
        // stored unredacted.
        'omit_uninspectable_bodies' => true,

        'max_header_value_bytes' => env('WIRETAP_HEADER_LIMIT', 4096),

        // Shorter echoed values are not swept from response bodies, because a
        // short token corrupts unrelated prose wherever it happens to appear.
        'min_echoed_secret_length' => 8,

        // A body that is omitted or truncated keeps a digest of itself only
        // as an HMAC under this key, so two calls can still be compared
        // without the digest being reversible. Unset, it is derived from
        // app.key (not app.key itself, which already keys sampling). Set it to
        // share digests across installs; set it to an empty string to keep
        // no digest at all.
        'hash_salt' => env('WIRETAP_HASH_SALT'),
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

    /*
    | The decision is keyed with a per-install secret, defaulting to app.key.
    |
    | Without one it is a pure function of the correlation id — which is
    | adopted from an inbound traceparent or X-Request-Id so traces join up
    | with the caller. That would let a caller compute an id offline that keeps
    | their own traffic out of the capture. Set this only if you would rather
    | not derive anything else from app.key.
    */
    'sampling_salt' => env('WIRETAP_SAMPLE_SALT'),

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
