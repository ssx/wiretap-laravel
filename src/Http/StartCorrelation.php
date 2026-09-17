<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Http;

use Closure;
use Illuminate\Http\Request;
use Ssx\Wiretap\Correlation;

/**
 * Seeds the correlation id from the inbound request.
 *
 * Every outbound call made while handling this request then shares one id, so
 * `wiretap trace <id>` can show the whole story rather than one call out of
 * context. Adopting an inbound traceparent means the trace also joins up with
 * whatever called us.
 *
 * Registered automatically by the service provider. Harmless if it runs twice.
 */
final class StartCorrelation
{
    public function handle(Request $request, Closure $next): mixed
    {
        Correlation::start($this->firstHeader($request, [
            'traceparent',
            'X-Request-Id',
            'X-Correlation-Id',
        ]));

        return $next($request);
    }

    /**
     * @param list<string> $names
     */
    private function firstHeader(Request $request, array $names): ?string
    {
        foreach ($names as $name) {
            $value = $request->header($name);

            if (is_array($value)) {
                $value = $value[0] ?? null;
            }

            if (is_string($value) && trim($value) !== '') {
                return $value;
            }
        }

        return null;
    }
}
