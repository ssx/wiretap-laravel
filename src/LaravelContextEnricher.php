<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel;

use Illuminate\Contracts\Foundation\Application;
use Ssx\Wiretap\Contract\ContextEnricher;
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
    public function __construct(private Application $app)
    {
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
    private function resolvedUserId(): string|int|null
    {
        if (!$this->app->bound('auth')) {
            return null;
        }

        try {
            $manager = $this->app->make('auth');

            if (!is_object($manager) || !method_exists($manager, 'guard')) {
                return null;
            }

            $guard = $manager->guard();

            if (!is_object($guard)
                || !method_exists($guard, 'hasUser')
                || !method_exists($guard, 'id')
                || !$guard->hasUser()) {
                return null;
            }

            $id = $guard->id();

            return is_string($id) || is_int($id) ? $id : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @return array<string, scalar|null>
     */
    private function consoleContext(): array
    {
        $argv = $_SERVER['argv'] ?? [];

        return array_filter([
            'command' => is_array($argv) && count($argv) > 1 ? (string) $argv[1] : null,
            'env' => (string) $this->app->environment(),
        ], static fn (mixed $v): bool => $v !== null && $v !== '');
    }

    /**
     * @return array<string, scalar|null>
     */
    private function requestContext(): array
    {
        if (!$this->app->bound('request')) {
            return [];
        }

        /** @var \Illuminate\Http\Request $request */
        $request = $this->app->make('request');
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
            'env' => (string) $this->app->environment(),
        ];

        // Resolving the user forces a session and a database query on routes
        // that do not otherwise need either, so only read what is already
        // resolved.
        $context['user_id'] = $this->resolvedUserId();

        return array_filter($context, static fn (mixed $v): bool => $v !== null && $v !== '');
    }
}
