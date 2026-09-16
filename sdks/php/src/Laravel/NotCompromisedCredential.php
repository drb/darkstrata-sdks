<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Laravel;

use Closure;
use Illuminate\Contracts\Validation\DataAwareRule;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\App;

/**
 * Validation rule for password set, change and reset forms.
 *
 *   'password' => ['required', 'confirmed', new NotCompromisedCredential()]
 *
 * The email is read from the request data (config darkstrata.email_field), or
 * pass it explicitly when the form has no email field, e.g. a change-password
 * form for the logged-in user: new NotCompromisedCredential($request->user()->email)
 */
final class NotCompromisedCredential implements ValidationRule, DataAwareRule
{
    private ?string $email;
    /** @var int|string|null */
    private $userId;
    private array $data = [];

    /** @param int|string|null $userId */
    public function __construct(?string $email = null, $userId = null)
    {
        $this->email = $email;
        $this->userId = $userId;
    }

    public function setData(array $data): static
    {
        $this->data = $data;
        return $this;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $config = App::make('config');
        if (!$config->get('darkstrata.validate_passwords', true) || !is_string($value)) {
            return;
        }

        $email = $this->email ?? $this->data[$config->get('darkstrata.email_field', 'email')] ?? null;

        if (App::make(CredentialChecker::class)->isCompromised(CredentialChecker::SOURCE_PASSWORD, is_string($email) ? $email : null, $value, $this->userId)) {
            $fail($config->get('darkstrata.messages.password'));
        }
    }
}
