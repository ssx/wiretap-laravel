<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Illuminate\Console\Command;

final class ShowCommand extends Command
{
    use RunsCoreCommand;

    protected $signature = 'wiretap:show
        {exchange : A position from wiretap:list, or an exchange id}
        {--curl : Print an equivalent curl command}
        {--har : Print HAR 1.2 for this exchange}
        {--json : Print the raw record}
        {--raw : Do not pretty-print bodies}';

    protected $description = 'Show one exchange in full';

    private static function asString(mixed $value): string
    {
        return is_array($value) ? (string) ($value[0] ?? '') : (string) $value;
    }

    public function handle(): int
    {
        return $this->runCore('show', array_merge(
            [self::asString($this->argument('exchange'))],
            $this->forwardOptions(['curl', 'har', 'json', 'raw']),
        ));
    }
}
