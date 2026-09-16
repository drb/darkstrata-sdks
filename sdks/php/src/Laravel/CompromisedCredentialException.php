<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

use Illuminate\Validation\ValidationException;

/**
 * Thrown from Auth::attempt() when login_action is 'deny'. It is an ordinary
 * ValidationException carrying the configured message on the email field, so
 * Breeze, Fortify and hand-written login controllers render it like a wrong
 * password, with the accurate wording.
 */
final class CompromisedCredentialException extends ValidationException
{
    public static function forLogin(string $field, string $message): self
    {
        return self::withMessages([$field => [$message]]);
    }
}
