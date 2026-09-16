<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

/** 401: invalid or expired API key. */
final class AuthenticationException extends DarkStrataException
{
    protected string $errorCode = self::CODE_AUTHENTICATION;
}
