<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Wiretap;

abstract class TestCase extends Orchestra
{
    protected string $logPath;

    protected function setUp(): void
    {
        $this->logPath = sys_get_temp_dir() . '/wiretap-laravel-' . bin2hex(random_bytes(6));

        parent::setUp();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->logPath . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->logPath);

        Wiretap::reset();

        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [WiretapServiceProvider::class];
    }

    /**
     * Per-test config, applied before the container boots.
     *
     * Setting config after boot and calling refreshApplication() does not work
     * here: the provider reads config during boot, so the override has to be
     * in place first.
     *
     * @var array<string, mixed>
     */
    protected array $wiretapConfig = [];

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['config']->set('wiretap.enabled', true);
        $app['config']->set('wiretap.path', $this->logPath);
        $app['config']->set('wiretap.presets', []);

        foreach ($this->wiretapConfig as $key => $value) {
            $app['config']->set($key, $value);
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    protected function bootWith(array $config): void
    {
        $this->wiretapConfig = $config;
        $this->refreshApplication();
    }
}
