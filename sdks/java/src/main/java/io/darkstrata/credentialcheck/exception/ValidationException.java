package io.darkstrata.credentialcheck.exception;

/**
 * Exception thrown when input validation fails.
 */
public class ValidationException extends DarkStrataException {

    private final String field;

    public ValidationException(String message) {
        this(message, null);
    }

    public ValidationException(String message, String field) {
        super(message, ErrorCode.VALIDATION_ERROR, null, false);
        this.field = field;
    }

    /**
     * Get the field that failed validation, if applicable.
     */
    public String getField() {
        return field;
    }
}
