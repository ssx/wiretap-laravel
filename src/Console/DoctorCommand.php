<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Illuminate\Console\Command;
use Ssx\Wiretap\Guzzle\Stack;
use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Recorder;

final class DoctorCommand extends Command
{
    use RunsCoreCommand;

    protected $signature = 'wiretap:doctor';

    protected $description = 'Report what is and is not being captured, and why';

    public function handle(Recorder $recorder): int
    {
        $this->line('');
        $this->line('<options=bold>Laravel integration</>');

        // The same interpretation the provider uses, not a plain cast.
        //
        // env() leaves "off" and "no" as strings, and (bool) 'off' is true —
        // so doctor reported capture as enabled while the provider had
        // correctly disabled it. The one command someone runs *because* they
        // are unsure whether capture is on was answering the opposite of the
        // truth.
        $enabled = WiretapServiceProvider::truthy(config('wiretap.enabled'));
        $this->row('capture enabled', $enabled ? 'yes' : 'no — set WIRETAP_ENABLED=true', $enabled);
        $this->row('recorder enabled', $recorder->isEnabled() ? 'yes' : 'no', $recorder->isEnabled());

        /** @var array<string, mixed> $capture */
        $capture = (array) config('wiretap.capture', []);
        $this->row('Http facade', ($capture['http_client'] ?? true) ? 'captured' : 'off', (bool) ($capture['http_client'] ?? true));
        $this->row('container Guzzle', ($capture['container_guzzle'] ?? true) ? 'captured' : 'off', (bool) ($capture['container_guzzle'] ?? true));

        $auto = class_exists(\Ssx\Wiretap\Auto\Wiretap::class);
        $this->row(
            'vendor code & raw curl',
            $auto ? 'ssx/wiretap-auto installed' : 'NOT captured — install ssx/wiretap-auto',
            $auto,
        );

        if (!$auto) {
            $this->line('    <fg=gray>A new GuzzleHttp\\Client() inside your vendor directory, and any</>');
            $this->line('    <fg=gray>raw curl_exec(), are invisible without it.</>');
        }

        $this->line('');

        // Everything else — PHP, extension, storage, traffic — is the same
        // question regardless of framework, so the core command answers it.
        return $this->runCore('doctor');
    }

    private function row(string $label, string $value, bool $ok): void
    {
        $this->line(sprintf(
            '  %s %-24s <fg=gray>%s</>',
            $ok ? '<fg=green>✓</>' : '<fg=yellow>!</>',
            $label,
            $value,
        ));
    }
}
