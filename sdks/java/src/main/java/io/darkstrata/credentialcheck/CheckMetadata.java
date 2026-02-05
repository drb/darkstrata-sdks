package io.darkstrata.credentialcheck;

import java.time.Instant;

/**
 * Metadata about a credential check operation.
 */
public class CheckMetadata {

    private final String prefix;
    private final int totalResults;
    private final HmacSource hmacSource;
    private final Long timeWindow;
    private final Long filterSince;
    private final boolean cachedResult;
    private final Instant checkedAt;

    private CheckMetadata(Builder builder) {
        this.prefix = builder.prefix;
        this.totalResults = builder.totalResults;
        this.hmacSource = builder.hmacSource;
        this.timeWindow = builder.timeWindow;
        this.filterSince = builder.filterSince;
        this.cachedResult = builder.cachedResult;
        this.checkedAt = builder.checkedAt;
    }

    /**
     * Get the 5-character hash prefix that was queried.
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * Get the total number of hashes matching the prefix.
     */
    public int getTotalResults() {
        return totalResults;
    }

    /**
     * Get the source of the HMAC key (SERVER or CLIENT).
     */
    public HmacSource getHmacSource() {
        return hmacSource;
    }

    /**
     * Get the server time window (if server HMAC was used).
     */
    public Long getTimeWindow() {
        return timeWindow;
    }

    /**
     * Get the epoch day used for filtering (if 'since' was provided).
     */
    public Long getFilterSince() {
        return filterSince;
    }

    /**
     * Check if this result was retrieved from cache.
     */
    public boolean isCachedResult() {
        return cachedResult;
    }

    /**
     * Get the timestamp when the check was performed.
     */
    public Instant getCheckedAt() {
        return checkedAt;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String prefix;
        private int totalResults;
        private HmacSource hmacSource;
        private Long timeWindow;
        private Long filterSince;
        private boolean cachedResult;
        private Instant checkedAt;

        private Builder() {
        }

        public Builder prefix(String prefix) {
            this.prefix = prefix;
            return this;
        }

        public Builder totalResults(int totalResults) {
            this.totalResults = totalResults;
            return this;
        }

        public Builder hmacSource(HmacSource hmacSource) {
            this.hmacSource = hmacSource;
            return this;
        }

        public Builder timeWindow(Long timeWindow) {
            this.timeWindow = timeWindow;
            return this;
        }

        public Builder filterSince(Long filterSince) {
            this.filterSince = filterSince;
            return this;
        }

        public Builder cachedResult(boolean cachedResult) {
            this.cachedResult = cachedResult;
            return this;
        }

        public Builder checkedAt(Instant checkedAt) {
            this.checkedAt = checkedAt;
            return this;
        }

        public CheckMetadata build() {
            return new CheckMetadata(this);
        }
    }
}
