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

    private static ?string $job = null;

    public static function command(?string $command = null, bool $set = false): ?string
    {
        if ($set) {
            self::$command = $command;
        }

        return self::$command;
    }

    public static function job(?string $job = null, bool $set = false): ?string
    {
        if ($set) {
            self::$job = $job;
        }

        return self::$job;
    }

    public static function reset(): void
    {
        self::$command = null;
        self::$job = null;
    }
}
