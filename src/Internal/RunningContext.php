<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Internal;

/**
 * What the process is currently doing, as the framework reported it.
 *
 * The enricher used to read `$_SERVER['argv'][1]`, which names the *process*
 * the call was made from rather than the thing that caused it: in a queue
 * worker that is "queue:work" for every job it ever handles, and under
 * `schedule:run` it is "schedule:run" for every scheduled command. Neither is
 * the answer someone reading a record wants.
 *
 * The provider's console and queue listeners set these as the framework tells
 * it what is starting, and clear them when it ends. Static because the
 * enricher is readonly and because there is exactly one of these per process.
 */
final class RunningContext
{
    private static ?string $command = null;

    /**
     * Jobs being processed, innermost last, keyed by job object id.
     *
     * A single value was wrong twice over. Only JobProcessed cleared it, so
     * after a failed job every later call in the process was attributed to
     * that job. And a job dispatched synchronously from inside another set it
     * to null when it finished, so the outer job's remaining calls named no
     * job at all.
     *
     * @var array<int, string>
     */
    private static array $jobs = [];

    public static function command(?string $command = null, bool $set = false): ?string
    {
        if ($set) {
            self::$command = $command;
        }

        return self::$command;
    }

    /**
     * The innermost job being processed, if any.
     */
    public static function job(): ?string
    {
        $last = array_key_last(self::$jobs);

        return $last === null ? null : self::$jobs[$last];
    }

    public static function pushJob(int $id, string $name): void
    {
        self::$jobs[$id] = $name;
    }

    /**
     * End a job, wherever it is in the stack. Ending one that is not there —
     * the second of a JobExceptionOccurred / JobFailed pair — does nothing.
     */
    public static function popJob(int $id): void
    {
        unset(self::$jobs[$id]);
    }

    public static function reset(): void
    {
        self::$command = null;
        self::$jobs = [];
    }
}
