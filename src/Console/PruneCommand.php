<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Illuminate\Console\Command;

/**
 * Schedule this. Captured payloads are personal data and Article 5(1)(e)
 * storage limitation applies to them, so retention is an obligation rather
 * than housekeeping.
 *
 *     $schedule->command('wiretap:prune')->daily();
 */
final class PruneCommand extends Command
{
    use RunsCoreCommand;

    protected $signature = 'wiretap:prune
        {--older-than= : Retention window, e.g. 7d. Defaults to config wiretap.retention_days}
        {--dry-run : Report what would be deleted without deleting it}';

    protected $description = 'Delete wiretap logs past the retention window';

    public function handle(): int
    {
        $option = $this->option('older-than');

        $window = is_string($option) && $option !== ''
            ? $option
            : sprintf('%dd', (int) config('wiretap.retention_days', 7));

        return $this->runCore('prune', array_merge(
            ['--older-than=' . $window],
            $this->forwardOptions(['dry-run']),
        ));
    }
}
