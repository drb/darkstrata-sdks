<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

final class NetworkException extends DarkStrataException
{
    protected string $errorCode = self::CODE_NETWORK;
    protected bool $retryable = true;
}
