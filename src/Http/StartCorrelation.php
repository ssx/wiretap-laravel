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
 * `wiretap trace <id>` shows the whole story rather than one call out of
 * context. Adopting an inbound traceparent joins the trace up with whatever
 * called us.
 */
final class StartCorrelation
{
    /**
     * Whether a request is being handled right now.
     *
     * The queue listener needs to know this, and cannot ask Correlation:
     * hasStarted() becomes true the moment anything calls Correlation::id(),
     * which the capture middleware does on the first outbound call. A single
     * boot-time HTTP request therefore made every subsequent job in a worker
     * look as though it had an enclosing scope, so none of them ever got their
     * own correlation.
     */
    private static bool $handling = false;

    public function handle(Request $request, Closure $next): mixed
    {
        $previous = self::$handling;

        // A request handled inside another one — a package re-entering
        // Kernel::handle() for multi-tenant routing or an API gateway — is
        // part of the outer request's work, and joins its correlation.
        //
        // Starting a new one here overwrote the outer id and restarted its
        // sequence at 0, and nothing put either back: the outer request's
        // remaining calls carried the inner request's id. Joining rather than
        // saving and restoring keeps the sequence strictly increasing through
        // the whole trace, so no two records share an (id, sequence) pair; and
        // core has no way to read or restore a sequence without consuming it.
        if (!$previous) {
            Correlation::start(
                $this->firstHeader($request, ['traceparent', 'X-Request-Id', 'X-Correlation-Id'])
            );
        }

        self::$handling = true;

        try {
            return $next($request);
        } finally {
            // Restored, not forced false. A package that re-enters
            // Kernel::handle() for a sub-request — multi-tenant routing, an
            // API gateway — left the outer request marked "not handling", so a
            // job dispatched later in that outer request took ownership of the
            // correlation and the request's remaining calls got a third,
            // unrelated id.
            self::$handling = $previous;
        }
    }

    public static function isHandlingRequest(): bool
    {
        return self::$handling;
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
