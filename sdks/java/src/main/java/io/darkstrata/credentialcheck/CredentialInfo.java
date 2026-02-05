package io.darkstrata.credentialcheck;

/**
 * Information about the credential that was checked.
 */
public class CredentialInfo {

    private final String email;
    private final boolean masked;

    public CredentialInfo(String email) {
        this.email = email;
        this.masked = true; // Password is always masked
    }

    /**
     * Get the email that was checked.
     */
    public String getEmail() {
        return email;
    }

    /**
     * Check if the password is masked (always true for security).
     */
    public boolean isMasked() {
        return masked;
    }

    @Override
    public String toString() {
        return "CredentialInfo{email='" + email + "', masked=" + masked + "}";
    }
}
