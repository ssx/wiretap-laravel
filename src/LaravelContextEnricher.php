<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel;

use Illuminate\Container\Container;
use Ssx\Wiretap\Contract\ContextEnricher;
use Ssx\Wiretap\Laravel\Http\StartCorrelation;
use Ssx\Wiretap\Exchange;

/**
 * Tags each exchange with the route or console command that caused it.
 *
 * The capture layers sit below the framework — the curl hooks run below the
 * container entirely — so they cannot know any of this. That is the whole
 * reason the enricher contract exists, and this context is usually what turns
 * "a slow call to some API" into "the checkout route is slow".
 */
final readonly class LaravelContextEnricher implements ContextEnricher
{
    /**
     * The container serving the call being recorded.
     *
     * Not the one captured when this enricher was constructed. Octane serves
     * each request from a sandbox clone and binds `request` on the clone, so
     * the boot-time container never sees it: every record came out tagged with
     * the boot request's context — in practice `command: octane:start` and no
     * route at all — which is the whole thing this class exists to provide.
     * A stale `auth` guard could likewise attribute one request's user to
     * another request's traffic.
     */
    private function container(): Container
    {
        return Container::getInstance();
    }

    public function enrich(Exchange $exchange): Exchange
    {
        try {
            // Deliberately not runningInConsole(). That is true under a test
            // runner simulating an HTTP request, and true in a queue worker
            // handling a job that has its own context — in both cases it would
            // report the wrong thing. The presence of a matched route is the
            // signal that actually distinguishes the two.
            $context = $this->requestContext();

            return $exchange->withContext($context === []
                ? $this->consoleContext()
                : $context);
        } catch (\Throwable) {
            // Enrichment is a nicety. Never let it cost a record, let alone
            // affect the application.
            return $exchange;
        }
    }

    /**
     * The authenticated user's id, but only when a guard already has one.
     *
     * Resolving the user would force a session and a database query on routes
     * that need neither, which is not a cost instrumentation should impose.
     *
     * The previous check asked method_exists() on the container's 'auth'
     * binding, which is AuthManager — it forwards guard methods through
     * __call(), so method_exists() was always false and the advertised user_id
     * was never captured at all.
     */
    private function resolvedUserId(): ?int
    {
        if (!$this->container()->bound('auth')) {
            return null;
        }

        try {
            $manager = $this->container()->make('auth');

            if (!is_object($manager) || !method_exists($manager, 'guard')) {
                return null;
            }

            // Only a guard the application has already built.
            //
            // Calling guard() constructs one and AuthManager caches it, so
            // enrichment could create the guard before the application was
            // ready to — a custom guard factory that reads request or tenant
            // state got built with whatever was set at the time of the first
            // outbound call, and the application then kept using that cached
            // instance. Instrumentation is not allowed to decide when a
            // guard comes into existence.
            $guard = self::resolvedGuard($manager);

            if ($guard === null
                || !method_exists($guard, 'hasUser')
                || !method_exists($guard, 'id')
                || !$guard->hasUser()) {
                return null;
            }

            $id = $guard->id();

            // Integers only.
            //
            // A string identifier is whatever the model's primary key is, and
            // email-as-primary-key is a real pattern — so `user_id` became
            // "alice@example.com", a direct identifier in plaintext in every
            // record. Core's email detector is off by default and this bridge
            // exposes no way to turn it on, so nothing downstream removed it
            // either. The README promises a user id; an id is what this
            // returns.
            return is_int($id) ? $id : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * A guard the application has already instantiated, or null.
     *
     * AuthManager exposes no way to ask, so its cache is read directly. Read
     * only, and a failure here just means no user id on the record.
     */
    private static function resolvedGuard(object $manager): ?object
    {
        try {
            $property = new \ReflectionProperty($manager, 'guards');
            $property->setAccessible(true);
            $guards = $property->getValue($manager);
        } catch (\Throwable) {
            return null;
        }

        if (!is_array($guards)) {
            return null;
        }

        foreach ($guards as $guard) {
            if (is_object($guard)) {
                return $guard;
            }
        }

        return null;
    }

    /**
     * @return array<string, scalar|null>
     */
    private function consoleContext(): array
    {
        // The command name only under the CLI SAPI.
        //
        // requestContext() returns nothing whenever no route matched, which
        // includes a 404 and any outbound call made before routing — so this
        // ran under the web SAPI too. And there PHP populates $_SERVER['argv']
        // from the query string, split on '+', whenever register_argc_argv is
        // on. That is the compiled-in default, active on any image shipping no
        // php.ini, the official php-fpm ones included:
        //
        //   GET /missing?q=aB3+xYz9qQ==   ->   argv = ["q=aB3", "xYz9qQ=="]
        //
        // which persisted half a caller-supplied token as `context.command`,
        // under a key nobody would think to look at.
        if (PHP_SAPI !== 'cli') {
            return array_filter([
                'env' => (string) $this->container()->make('app')->environment(),
            ], static fn (mixed $v): bool => $v !== '');
        }

        $argv = $_SERVER['argv'] ?? [];

        return array_filter([
            'command' => is_array($argv) && count($argv) > 1 ? (string) $argv[1] : null,
            'env' => (string) $this->container()->make('app')->environment(),
        ], static fn (mixed $v): bool => $v !== null && $v !== '');
    }

    /**
     * @return array<string, scalar|null>
     */
    private function requestContext(): array
    {
        if (!$this->container()->bound('request')) {
            return [];
        }

        // Only while a request is actually being handled.
        //
        // The container keeps the last request, and its matched route, long
        // after the response has gone. Every outbound call made afterwards was
        // therefore tagged with that route — harmless under FPM, but under
        // Octane it meant each inter-request call, and each job run in the same
        // worker, was attributed to whichever request happened to run before
        // it.
        if (!StartCorrelation::isHandlingRequest()) {
            return [];
        }

        /** @var \Illuminate\Http\Request $request */
        $request = $this->container()->make('request');
        $route = $request->route();

        // No matched route means this is not an HTTP request being handled —
        // a console command, a queue job, a boot-time call.
        if (!is_object($route)) {
            return [];
        }

        $context = [
            'route' => method_exists($route, 'getName') ? $route->getName() : null,
            'action' => method_exists($route, 'getActionName') ? $route->getActionName() : null,
            'method' => $request->getMethod(),
            // The route template, not the concrete path. `/reset-password/{token}`
            // rather than `/reset-password/<the actual token>` — recording the
            // real path put a credential into context, which no body-path rule
            // can protect.
            'uri' => '/' . ltrim(method_exists($route, 'uri') ? (string) $route->uri() : $request->path(), '/'),
            'env' => (string) $this->container()->make('app')->environment(),
        ];

        // Resolving the user forces a session and a database query on routes
        // that do not otherwise need either, so only read what is already
        // resolved.
        $context['user_id'] = $this->resolvedUserId();

        return array_filter($context, static fn (mixed $v): bool => $v !== null && $v !== '');
    }
}
