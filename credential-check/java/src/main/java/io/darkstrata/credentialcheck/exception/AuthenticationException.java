package io.darkstrata.credentialcheck.exception;

/**
 * Exception thrown when API authentication fails (401).
 */
public class AuthenticationException extends DarkStrataException {

    public AuthenticationException() {
        this("Invalid or missing API key");
    }

    public AuthenticationException(String message) {
        super(message, ErrorCode.AUTHENTICATION_ERROR, 401, false);
    }
}
