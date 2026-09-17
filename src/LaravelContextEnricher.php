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
        if ($this->app->bound('auth')) {
            $guard = $this->app->make('auth');

            if (is_object($guard) && method_exists($guard, 'hasUser') && $guard->hasUser()) {
                /** @var mixed $id */
                $id = method_exists($guard, 'id') ? $guard->id() : null;
                $context['user_id'] = is_scalar($id) ? $id : null;
            }
        }

        return array_filter($context, static fn (mixed $v): bool => $v !== null && $v !== '');
    }
}
