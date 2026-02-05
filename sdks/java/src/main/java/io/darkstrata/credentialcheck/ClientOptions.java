package io.darkstrata.credentialcheck;

/**
 * Configuration options for the DarkStrata client.
 */
public class ClientOptions {

    private final String apiKey;
    private final String baseUrl;
    private final long timeout;
    private final int retries;
    private final boolean enableCaching;
    private final long cacheTTL;

    private ClientOptions(Builder builder) {
        this.apiKey = builder.apiKey;
        this.baseUrl = builder.baseUrl;
        this.timeout = builder.timeout;
        this.retries = builder.retries;
        this.enableCaching = builder.enableCaching;
        this.cacheTTL = builder.cacheTTL;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public long getTimeout() {
        return timeout;
    }

    public int getRetries() {
        return retries;
    }

    public boolean isEnableCaching() {
        return enableCaching;
    }

    public long getCacheTTL() {
        return cacheTTL;
    }

    /**
     * Create a new builder with the required API key.
     */
    public static Builder builder(String apiKey) {
        return new Builder(apiKey);
    }

    public static class Builder {
        private final String apiKey;
        private String baseUrl = Constants.DEFAULT_BASE_URL;
        private long timeout = Constants.DEFAULT_TIMEOUT;
        private int retries = Constants.DEFAULT_RETRIES;
        private boolean enableCaching = true;
        private long cacheTTL = Constants.DEFAULT_CACHE_TTL;

        private Builder(String apiKey) {
            this.apiKey = apiKey;
        }

        /**
         * Set the base URL for the API (default: https://api.darkstrata.io/v1/).
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * Set the request timeout in milliseconds (default: 30000).
         */
        public Builder timeout(long timeout) {
            this.timeout = timeout;
            return this;
        }

        /**
         * Set the number of retry attempts (default: 3).
         */
        public Builder retries(int retries) {
            this.retries = retries;
            return this;
        }

        /**
         * Enable or disable caching (default: true).
         */
        public Builder enableCaching(boolean enableCaching) {
            this.enableCaching = enableCaching;
            return this;
        }

        /**
         * Set the cache TTL in milliseconds (default: 3600000 = 1 hour).
         */
        public Builder cacheTTL(long cacheTTL) {
            this.cacheTTL = cacheTTL;
            return this;
        }

        public ClientOptions build() {
            return new ClientOptions(this);
        }
    }
}
