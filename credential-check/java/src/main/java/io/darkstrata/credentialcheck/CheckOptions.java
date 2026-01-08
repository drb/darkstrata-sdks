package io.darkstrata.credentialcheck;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;

/**
 * Options for individual check operations.
 */
public class CheckOptions {

    private final String clientHmac;
    private final Long since;

    private CheckOptions(Builder builder) {
        this.clientHmac = builder.clientHmac;
        this.since = builder.since;
    }

    /**
     * Get the client-provided HMAC key (at least 64 hex characters).
     */
    public String getClientHmac() {
        return clientHmac;
    }

    /**
     * Get the 'since' filter as epoch day (days since 1970-01-01).
     */
    public Long getSince() {
        return since;
    }

    /**
     * Create a new builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String clientHmac;
        private Long since;

        private Builder() {
        }

        /**
         * Set a client-provided HMAC key (at least 64 hex characters / 256 bits).
         */
        public Builder clientHmac(String clientHmac) {
            this.clientHmac = clientHmac;
            return this;
        }

        /**
         * Filter results to only include breaches since the given epoch day.
         */
        public Builder since(long epochDay) {
            this.since = epochDay;
            return this;
        }

        /**
         * Filter results to only include breaches since the given date.
         */
        public Builder since(LocalDate date) {
            this.since = date.toEpochDay();
            return this;
        }

        /**
         * Filter results to only include breaches since the given instant.
         */
        public Builder since(Instant instant) {
            this.since = instant.atZone(ZoneOffset.UTC).toLocalDate().toEpochDay();
            return this;
        }

        public CheckOptions build() {
            return new CheckOptions(this);
        }
    }
}
