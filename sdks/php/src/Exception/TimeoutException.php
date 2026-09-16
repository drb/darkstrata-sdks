<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

final class TimeoutException extends DarkStrataException
{
    protected string $errorCode = self::CODE_TIMEOUT;
    protected bool $retryable = true;
}
