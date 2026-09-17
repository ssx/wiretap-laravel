<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Illuminate\Console\Command;

final class ExportCommand extends Command
{
    use RunsCoreCommand;

    protected $signature = 'wiretap:export
        {--host= : Only this host}
        {--status= : Exact status, or a class such as 5xx}
        {--failed : Transport errors and 4xx/5xx only}
        {--since= : Relative window, e.g. 30m, 2h, 7d}
        {--limit=200 : Maximum results}
        {--out= : Write to this file instead of stdout}';

    protected $description = 'Export exchanges as HAR 1.2 for DevTools, Proxyman, Insomnia or Postman';

    public function handle(): int
    {
        return $this->runCore('export', $this->forwardOptions([
            'host', 'status', 'failed', 'since', 'limit', 'out',
        ]));
    }
}
