<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Illuminate\Console\Command;

final class ListCommand extends Command
{
    use RunsCoreCommand;

    protected $signature = 'wiretap:list
        {--host= : Only this host}
        {--method= : Only this HTTP method}
        {--status= : Exact status, or a class such as 5xx}
        {--failed : Transport errors and 4xx/5xx only}
        {--since= : Relative window, e.g. 30m, 2h, 7d}
        {--limit=20 : Maximum results}';

    protected $description = 'List recorded outbound HTTP exchanges, newest first';

    public function handle(): int
    {
        return $this->runCore('list', $this->forwardOptions([
            'host', 'method', 'status', 'failed', 'since', 'limit',
        ]));
    }
}
