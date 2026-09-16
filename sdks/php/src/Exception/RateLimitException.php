<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

/** 429: rate limit exceeded. */
final class RateLimitException extends DarkStrataException
{
    protected string $errorCode = self::CODE_RATE_LIMIT;
    protected bool $retryable = true;
    private int $retryAfter;

    public function __construct(string $message, int $retryAfterSeconds = 0)
    {
        $this->retryAfter = $retryAfterSeconds;
        parent::__construct("{$message} (retry after: {$retryAfterSeconds}s)");
    }

    /** Seconds from the Retry-After header, or 0 if absent. */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
