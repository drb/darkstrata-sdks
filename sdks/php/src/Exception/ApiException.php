<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

use DarkStrata\CredentialCheck\Constants;

/** Non-2xx API response other than 401/429. */
final class ApiException extends DarkStrataException
{
    protected string $errorCode = self::CODE_API;
    private int $statusCode;
    private string $responseBody;

    public function __construct(int $statusCode, string $message, string $responseBody = '')
    {
        $this->statusCode = $statusCode;
        $this->responseBody = $responseBody;
        $this->retryable = in_array($statusCode, Constants::RETRYABLE_STATUS_CODES, true);
        parent::__construct("{$message} (status: {$statusCode})");
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function getResponseBody(): string
    {
        return $this->responseBody;
    }
}
