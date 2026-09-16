<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

/** Dispatched on every hit so you can run your own workflow: alert, lock the account, open a ticket. */
final class CompromisedCredentialDetected
{
    /** CredentialChecker::SOURCE_LOGIN or SOURCE_PASSWORD */
    public string $source;
    public string $email;
    /** @var int|string|null */
    public $userId;

    /** @param int|string|null $userId */
    public function __construct(string $source, string $email, $userId = null)
    {
        $this->source = $source;
        $this->email = $email;
        $this->userId = $userId;
    }
}
