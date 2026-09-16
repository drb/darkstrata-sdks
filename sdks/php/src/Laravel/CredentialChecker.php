<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Exception\DarkStrataException;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Psr\Log\LoggerInterface;

/**
 * Single gate every hook goes through: config guard, SDK call, fail-open handling, event.
 */
final class CredentialChecker
{
    public const SOURCE_LOGIN = 'login';
    public const SOURCE_PASSWORD = 'password';

    private Container $app;
    private Repository $config;
    private LoggerInterface $logger;
    /** @var array<string, bool> memoised per request so a repeated check costs one API call and one event */
    private array $seen = [];

    public function __construct(Container $app, Repository $config, LoggerInterface $logger)
    {
        $this->app = $app;
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * True when the pair is in the breach corpus. False when the check is unconfigured, or
     * fails and fail_open is set. Rethrows the SDK exception when fail_open is false.
     *
     * @param int|string|null $userId
     */
    public function isCompromised(string $source, ?string $email, ?string $password, $userId = null): bool
    {
        if (empty($this->config->get('darkstrata.api_key')) || $email === null || trim($email) === '' || $password === null || $password === '') {
            return false;
        }

        $key = hash('sha256', "{$source}\n{$email}\n{$password}");
        if (!isset($this->seen[$key])) {
            $this->seen[$key] = $this->check($source, $email, $password, $userId);
        }
        return $this->seen[$key];
    }

    /** @param int|string|null $userId */
    private function check(string $source, string $email, string $password, $userId): bool
    {
        try {
            // Resolved per call so a client swapped in after boot (tests, tenancy) is honoured.
            $found = $this->app->make(Client::class)->check($email, $password)->found;
        } catch (DarkStrataException $e) {
            if (!$this->config->get('darkstrata.fail_open', true)) {
                throw $e;
            }
            $this->logger->warning("DarkStrata credential check failed ({$e->getErrorCode()}); allowing because fail_open is enabled", ['exception' => $e]);
            return false;
        }

        if ($found) {
            $this->logger->warning("Compromised credential detected for {$email} via {$source}");
            // Resolved per call so Event::fake() in a host app's tests sees it.
            $this->app->make('events')->dispatch(new CompromisedCredentialDetected($source, $email, $userId));
        }
        return $found;
    }
}
