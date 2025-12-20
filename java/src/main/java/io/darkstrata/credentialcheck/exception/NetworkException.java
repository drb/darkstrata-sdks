package io.darkstrata.credentialcheck.exception;

/**
 * Exception thrown when a network error occurs.
 */
public class NetworkException extends DarkStrataException {

    public NetworkException(String message) {
        this(message, null);
    }

    public NetworkException(String message, Throwable cause) {
        super(message, ErrorCode.NETWORK_ERROR, null, true, cause);
    }
}
