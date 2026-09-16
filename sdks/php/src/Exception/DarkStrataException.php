<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

class DarkStrataException extends \RuntimeException
{
    public const CODE_AUTHENTICATION = 'AUTHENTICATION_ERROR';
    public const CODE_VALIDATION = 'VALIDATION_ERROR';
    public const CODE_API = 'API_ERROR';
    public const CODE_TIMEOUT = 'TIMEOUT_ERROR';
    public const CODE_NETWORK = 'NETWORK_ERROR';
    public const CODE_RATE_LIMIT = 'RATE_LIMIT_ERROR';

    protected string $errorCode = 'UNKNOWN_ERROR';
    protected bool $retryable = false;

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct("[{$this->errorCode}] {$message}", 0, $previous);
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function isRetryable(): bool
    {
        return $this->retryable;
    }
}
