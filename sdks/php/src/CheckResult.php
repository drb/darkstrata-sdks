<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck;

final class CheckResult
{
    /** True if the credential appears in a known breach. */
    public bool $found;
    /** Email as supplied, or "[hash-only]" for hash checks. Never sent to the API. */
    public string $email;
    /** Prefix (5-6 chars) that was sent to the API. */
    public string $prefix;
    /** Number of candidate hashes the API returned for the prefix. */
    public int $totalResults;
    /** 'server' or 'client'. */
    public string $hmacSource;
    public string $timeWindow;
    /** Epoch-day filter applied, or null. */
    public ?int $filterSince;
    public bool $cachedResult;
    public \DateTimeImmutable $checkedAt;

    /** @internal */
    public function __construct(bool $found, string $email, array $headers, bool $cached)
    {
        $this->found = $found;
        $this->email = $email;
        $this->prefix = $headers['prefix'];
        $this->totalResults = $headers['totalResults'];
        $this->hmacSource = $headers['hmacSource'];
        $this->timeWindow = $headers['timeWindow'];
        $this->filterSince = $headers['filterSince'];
        $this->cachedResult = $cached;
        $this->checkedAt = new \DateTimeImmutable();
    }
}
