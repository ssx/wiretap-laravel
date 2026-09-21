<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Illuminate\Console\Command;

final class TraceCommand extends Command
{
    use RunsCoreCommand;

    protected $signature = 'wiretap:trace
        {correlation : The correlation id}
        {--limit=200 : Maximum results}';

    protected $description = 'Every outbound call made during one inbound request';

    private static function asString(mixed $value): string
    {
        return is_array($value) ? (string) ($value[0] ?? '') : (string) $value;
    }

    public function handle(): int
    {
        return $this->runCore(
            'trace',
            $this->forwardOptions(['limit']),
            [self::asString($this->argument('correlation'))],
        );
    }
}
