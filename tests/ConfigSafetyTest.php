<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Recorder;

/**
 * @return list<array<string, mixed>>
 */
function recordsUnder(string $path): array
{
    $records = [];

    foreach (glob($path . '/*.ndjson') ?: [] as $file) {
        foreach (file($file) ?: [] as $line) {
            $records[] = json_decode($line, true);
        }
    }

    return $records;
}

/**
 * The redaction config the booted provider actually built.
 */
function configuredRedaction(Illuminate\Contracts\Foundation\Application $app): Ssx\Wiretap\Redaction\RedactionConfig
{
    $redactor = $app->make(Recorder::class)->redactor();

    return (new ReflectionProperty($redactor, 'config'))->getValue($redactor);
}

function removeTree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);

        return;
    }

    foreach (glob($path . '/{,.}[!.,!..]*', GLOB_BRACE) ?: [] as $child) {
        removeTree($child);
    }

    @rmdir($path);
}

describe('a relative log path', function (): void {
    beforeEach(function (): void {
        $this->scratch = sys_get_temp_dir() . '/wiretap-relative-' . bin2hex(random_bytes(6));
        mkdir($this->scratch . '/public', 0777, true);
        $this->cwd = (string) getcwd();
    });

    afterEach(function (): void {
        chdir($this->cwd);
        removeTree($this->scratch);
    });

    it('resolves against the application base, not the working directory', function (): void {
        // Under php-fpm the working directory is public/, so a relative
        // WIRETAP_PATH put complete captures inside the web root, where the
        // webserver serves them to anyone.
        $relative = 'wiretap-relative-' . bin2hex(random_bytes(4));
        $this->bootWith(['wiretap.path' => $relative]);
        chdir($this->scratch . '/public');

        Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
        Http::get('https://api.example.test/relative');
        $this->app->make(Recorder::class)->flush();

        $inBase = recordsUnder(base_path($relative));
        removeTree(base_path($relative));

        expect(recordsUnder($this->scratch . '/public/' . $relative))->toBe([])
            ->and($inBase)->toHaveCount(1)
            ->and(WiretapServiceProvider::path(['path' => $relative]))->toBe(base_path($relative));
    });

    it('is judged by doctor where it will actually be written', function (): void {
        $this->app->setBasePath($this->scratch);
        $this->app->usePublicPath($this->scratch . '/public');
        config(['wiretap.path' => 'public/wiretap']);

        Artisan::call('wiretap:doctor');

        expect(Artisan::output())->toContain('INSIDE the web root');
    });
});

describe('doctor and the web root', function (): void {
    beforeEach(function (): void {
        $this->scratch = sys_get_temp_dir() . '/wiretap-webroot-' . bin2hex(random_bytes(6));
        mkdir($this->scratch . '/releases/7/public', 0777, true);
        symlink($this->scratch . '/releases/7', $this->scratch . '/current');
    });

    afterEach(function (): void {
        removeTree($this->scratch);
    });

    it('sees through a symlinked release to a directory not created yet', function (): void {
        // realpath() fails for a directory that does not exist yet, so the raw
        // symlinked path was compared with the resolved web root and never
        // matched.
        $this->app->usePublicPath($this->scratch . '/current/public');
        config(['wiretap.path' => $this->scratch . '/current/public/wiretap']);

        Artisan::call('wiretap:doctor');

        expect(Artisan::output())->toContain('INSIDE the web root');
    });

    it('does not mistake a sibling of the web root for the web root', function (): void {
        // A bare prefix test put /srv/app/public-logs inside /srv/app/public.
        mkdir($this->scratch . '/releases/7/public-logs');
        $this->app->usePublicPath($this->scratch . '/releases/7/public');
        config(['wiretap.path' => $this->scratch . '/releases/7/public-logs']);

        Artisan::call('wiretap:doctor');

        expect(Artisan::output())->not->toContain('INSIDE the web root');
    });
});

describe('header allowlist', function (): void {
    it('keeps only the headers it names', function (): void {
        // The default denylist was merged into the allowlist, so X-Api-Key,
        // Authorization and the rest were all "allowed". Short credentials
        // then escaped the echoed-secret sweep too.
        $this->bootWith([
            'wiretap.redaction.header_mode' => 'allow',
            'wiretap.redaction.headers' => ['Content-Type'],
        ]);

        Http::fake(fn () => Http::response('{}', 200, ['Content-Type' => 'application/json']));
        Http::withHeaders(['X-Api-Key' => 'abc123', 'Authorization' => 'Basic Zm9vOmJhcg=='])
            ->get('https://api.example.test/allow');

        $recorder = $this->app->make(Recorder::class);
        $recorder->flush();
        $record = json_encode(recordsUnder($this->logPath));

        expect($record)->not->toContain('abc123')
            ->and($record)->not->toContain('Zm9vOmJhcg==');
    });

    it('still adds to the denylist in deny mode', function (): void {
        $this->bootWith(['wiretap.redaction.headers' => ['X-Partner-Secret']]);

        $config = configuredRedaction($this->app);

        expect($config->headers)->toContain('x-partner-secret')
            ->and($config->headers)->toContain('authorization');
    });
});

describe('protective switches', function (): void {
    it('keeps a protection on for a value it does not recognise', function (string $key, mixed $value): void {
        // truthy() maps anything unrecognised to false, which is right for
        // "enabled" and exactly wrong for a switch whose "on" is the safe
        // state: WIRETAP_REDACT=treu turned redaction off entirely.
        $this->bootWith([$key => $value]);

        $config = configuredRedaction($this->app);
        $property = [
            'wiretap.redaction.enabled' => 'enabled',
            'wiretap.redaction.safety_net' => 'safetyNet',
            'wiretap.redaction.omit_uninspectable_bodies' => 'omitUninspectableBodies',
        ][$key];

        expect($config->{$property})->toBeTrue();
    })->with([
        ['wiretap.redaction.enabled', 'treu'],
        ['wiretap.redaction.enabled', 'ture'],
        ['wiretap.redaction.enabled', ''],
        ['wiretap.redaction.enabled', null],
        ['wiretap.redaction.safety_net', 'yes please'],
        ['wiretap.redaction.omit_uninspectable_bodies', 'nope'],
    ]);

    it('turns a protection off only when told to in a way it recognises', function (mixed $value): void {
        $this->bootWith(['wiretap.redaction.enabled' => $value]);

        expect(configuredRedaction($this->app)->enabled)->toBeFalse();
    })->with([[false], ['false'], ['FALSE'], ['0'], [0], ['off'], ['no'], [' Off ']]);

    it('keeps the default header mode for one it does not recognise', function (): void {
        $this->bootWith(['wiretap.redaction.header_mode' => 'alow']);

        expect(configuredRedaction($this->app)->headerMode)->toBe('deny');
    });

    it('recognises an allowlist however it is capitalised', function (): void {
        $this->bootWith(['wiretap.redaction.header_mode' => ' Allow ']);

        expect(configuredRedaction($this->app)->headerMode)->toBe('allow');
    });
});
