<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;

/**
 * Attempting carries the plaintext credentials but fires before the password is
 * verified; Validated fires after verification but without the password. Stash
 * on the first, check on the second, so only correct passwords cost an API call.
 */
final class LoginSubscriber
{
    private CredentialChecker $checker;
    private Repository $config;
    /** @var array{0: string, 1: string}|null */
    private ?array $pending = null;

    public function __construct(CredentialChecker $checker, Repository $config)
    {
        $this->checker = $checker;
        $this->config = $config;
    }

    public function subscribe(Dispatcher $events): void
    {
        $events->listen(Attempting::class, [$this, 'onAttempting']);
        $events->listen(Validated::class, [$this, 'onValidated']);
    }

    public function onAttempting(Attempting $event): void
    {
        $field = $this->config->get('darkstrata.email_field', 'email');
        $email = $event->credentials[$field] ?? $event->credentials['email'] ?? $event->credentials['username'] ?? null;
        $password = $event->credentials['password'] ?? null;
        $this->pending = is_string($email) && is_string($password) ? [$email, $password] : null;
    }

    public function onValidated(Validated $event): void
    {
        if ($this->pending === null) {
            return;
        }
        [$email, $password] = $this->pending;
        $this->pending = null;

        $compromised = $this->checker->isCompromised(
            CredentialChecker::SOURCE_LOGIN,
            $email,
            $password,
            $event->user->getAuthIdentifier()
        );

        if ($compromised && $this->config->get('darkstrata.login_action', 'deny') === 'deny') {
            throw CompromisedCredentialException::forLogin(
                $this->config->get('darkstrata.email_field', 'email'),
                $this->config->get('darkstrata.messages.login')
            );
        }
    }
}
