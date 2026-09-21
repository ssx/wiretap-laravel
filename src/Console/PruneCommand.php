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

        if (is_string($option) && $option !== '') {
            $window = $option;
        } else {
            // Validated, not cast.
            //
            // (int) turns '', null and 'seven' all into 0, which becomes
            // --older-than=0d — a cutoff of "now", so core deleted every file
            // including the one currently being written to, reported success
            // and exited 0. WIRETAP_RETENTION_DAYS= left blank in .env is
            // enough to trigger it, and the docblock above tells operators to
            // schedule this daily. Core rejects --older-than=nonsense; 0d is
            // the hole this command drove through.
            $days = filter_var(config('wiretap.retention_days', 7), FILTER_VALIDATE_INT);

            if ($days === false || $days < 1) {
                $this->error('wiretap.retention_days must be a positive integer of days.');

                return self::FAILURE;
            }

            $window = sprintf('%dd', $days);
        }

        return $this->runCore('prune', array_merge(
            ['--older-than=' . $window],
            $this->forwardOptions(['dry-run']),
        ));
    }
}
