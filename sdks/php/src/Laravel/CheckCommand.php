<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Exception\DarkStrataException;
use Illuminate\Console\Command;

/** Health check: confirms the API key is configured and accepted. */
final class CheckCommand extends Command
{
    protected $signature = 'darkstrata:check';
    protected $description = 'Verify the DarkStrata API key and connectivity';

    public function handle(): int
    {
        if (empty($this->laravel['config']['darkstrata.api_key'])) {
            $this->error('No API key configured. Set DARKSTRATA_API_KEY or config darkstrata.api_key.');
            return self::FAILURE;
        }

        try {
            $result = $this->laravel->make(Client::class)->check('healthcheck@darkstrata.io', 'healthcheck');
        } catch (DarkStrataException $e) {
            $this->error("DarkStrata API check failed: {$e->getMessage()}");
            return self::FAILURE;
        }

        $this->info("DarkStrata API key accepted. Prefix {$result->prefix} returned {$result->totalResults} candidates.");
        return self::SUCCESS;
    }
}
