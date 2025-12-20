package io.darkstrata.credentialcheck;

/**
 * Result of a credential check operation.
 */
public class CheckResult {

    private final boolean found;
    private final CredentialInfo credential;
    private final CheckMetadata metadata;

    private CheckResult(Builder builder) {
        this.found = builder.found;
        this.credential = builder.credential;
        this.metadata = builder.metadata;
    }

    /**
     * Check if the credential was found in the breach database.
     */
    public boolean isFound() {
        return found;
    }

    /**
     * Get information about the credential that was checked.
     */
    public CredentialInfo getCredential() {
        return credential;
    }

    /**
     * Get metadata about the check operation.
     */
    public CheckMetadata getMetadata() {
        return metadata;
    }

    @Override
    public String toString() {
        return "CheckResult{found=" + found + ", credential=" + credential + ", metadata=" + metadata + "}";
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private boolean found;
        private CredentialInfo credential;
        private CheckMetadata metadata;

        private Builder() {
        }

        public Builder found(boolean found) {
            this.found = found;
            return this;
        }

        public Builder credential(CredentialInfo credential) {
            this.credential = credential;
            return this;
        }

        public Builder metadata(CheckMetadata metadata) {
            this.metadata = metadata;
            return this;
        }

        public CheckResult build() {
            return new CheckResult(this);
        }
    }
}
