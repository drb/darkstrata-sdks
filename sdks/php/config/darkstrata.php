<?php

return [
    // Required. With no key every check is skipped and one warning is logged at boot.
    'api_key' => env('DARKSTRATA_API_KEY'),

    'base_url' => env('DARKSTRATA_BASE_URL', 'https://api.darkstrata.io/v1/'),

    // Let the NotCompromisedCredential validation rule reject compromised pairs
    // when a password is set or changed.
    'validate_passwords' => env('DARKSTRATA_VALIDATE_PASSWORDS', true),

    // Check every successful Auth::attempt() before the session is started.
    'check_logins' => env('DARKSTRATA_CHECK_LOGINS', true),

    // 'deny' throws CompromisedCredentialException (a ValidationException on the
    // email field) so the login fails. 'warn' allows it, logs a warning and
    // dispatches CompromisedCredentialDetected.
    'login_action' => env('DARKSTRATA_LOGIN_ACTION', 'deny'),

    // If the DarkStrata API is unreachable, allow the operation. Set false to reject instead.
    'fail_open' => env('DARKSTRATA_FAIL_OPEN', true),

    // The credentials key / request field that holds the email address.
    'email_field' => 'email',

    // Shown to the person. The pair is breached, not just the password, so
    // point them at a reset rather than only refusing them.
    'messages' => [
        'login' => 'This email address and password have appeared together in a data breach. Reset your password to sign in, and change it anywhere else you have used it.',
        'password' => 'This email address and password have appeared together in a data breach. Choose a different password, and change it anywhere else you have used it.',
    ],
];
