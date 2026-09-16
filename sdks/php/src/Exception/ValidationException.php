<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Exception;

final class ValidationException extends DarkStrataException
{
    protected string $errorCode = self::CODE_VALIDATION;
    private string $field;

    public function __construct(string $field, string $message)
    {
        $this->field = $field;
        parent::__construct("{$message} (field: {$field})");
    }

    public function getField(): string
    {
        return $this->field;
    }
}
