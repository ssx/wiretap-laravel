<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Laravel\Console;

use Ssx\Wiretap\Cli\Application;
use Ssx\Wiretap\Laravel\WiretapServiceProvider;
use Ssx\Wiretap\Cli\Output;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs a core CLI command from inside artisan.
 *
 * These are deliberately thin. Reimplementing the rendering against Laravel's
 * table helper would mean two implementations of every command drifting apart,
 * and the core CLI already knows how to print an exchange. The artisan command
 * exists so `php artisan wiretap:list` works with the app's configured path
 * without anyone having to remember where that is.
 */
trait RunsCoreCommand
{
    /**
     * @param list<string> $arguments  Options, forwarded as written
     * @param list<string> $positional Values, passed after `--`
     */
    protected function runCore(string $command, array $arguments = [], array $positional = []): int
    {
        // The same resolution the sink uses.
        //
        // A raw cast turned a blank configured path into '', which core does
        // not treat as absent — `--path=` is not null — so the recorder wrote
        // to its default directory while every artisan command read an empty
        // one and reported no exchanges.
        $path = WiretapServiceProvider::path((array) config('wiretap', []));
        // Positionals go last, after a `--`.
        //
        // A correlation id beginning with a dash was otherwise read as a short
        // option cluster: `wiretap:trace -abc` reported "Which correlation?"
        // for an argument that had been supplied. Ids come from inbound
        // headers and core keeps a leading dash when it normalises one, so
        // this was reachable rather than theoretical.
        $argv = array_merge(['wiretap', $command], $arguments, ['--path=' . $path]);

        if ($positional !== []) {
            $argv = array_merge($argv, ['--'], $positional);
        }

        // Capture the core CLI's output and replay it through Laravel's.
        //
        // Writing to STDOUT directly meant Artisan::call('wiretap:export') sent
        // the HAR to process stdout while Artisan::output() came back empty, so
        // buffered output and console assertions could not see any of it.
        $stream = fopen('php://memory', 'w+');

        if ($stream === false) {
            return (new Application())->run($argv);
        }

        try {
            $exitCode = (new Application(new Output(
                $stream,
                // Match Laravel's decision about colour rather than sniffing
                // the stream, which is never a TTY.
                decorated: $this->output->isDecorated(),
            )))->run($argv);

            rewind($stream);
            $captured = stream_get_contents($stream);

            if (is_string($captured) && $captured !== '') {
                // OUTPUT_RAW, because Symfony's default write() interprets
                // console tags. A HAR body containing <info>x</info> was
                // replayed as plain "x" — an export silently losing content,
                // and with decoration on it gained ANSI bytes that made the
                // JSON invalid. The core renderer has already decided about
                // colour.
                $this->output->write($captured, false, OutputInterface::OUTPUT_RAW);
            }

            return $exitCode;
        } finally {
            fclose($stream);
        }
    }

    /**
     * Pass through any option the core command understands, so the artisan
     * wrapper never has to be updated when the core grows a filter.
     *
     * @param list<string> $names
     *
     * @return list<string>
     */
    protected function forwardOptions(array $names): array
    {
        $forwarded = [];

        foreach ($names as $name) {
            $value = $this->option($name);

            if ($value === null || $value === false || $value === []) {
                continue;
            }

            if ($value === true) {
                $forwarded[] = "--{$name}";

                continue;
            }

            // An option can arrive as an array when declared with `*`. None of
            // ours are, but narrowing here keeps the contract honest.
            $forwarded[] = sprintf('--%s=%s', $name, is_array($value) ? implode(',', $value) : (string) $value);
        }

        return $forwarded;
    }
}
