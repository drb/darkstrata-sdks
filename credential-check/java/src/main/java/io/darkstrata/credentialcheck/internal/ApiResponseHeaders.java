package io.darkstrata.credentialcheck.internal;

import io.darkstrata.credentialcheck.HmacSource;

/**
 * Parsed response headers from the API.
 */
public class ApiResponseHeaders {

    private final String prefix;
    private final String hmacKey;
    private final HmacSource hmacSource;
    private final Long timeWindow;
    private final int totalResults;
    private final Long filterSince;

    public ApiResponseHeaders(
            String prefix,
            String hmacKey,
            HmacSource hmacSource,
            Long timeWindow,
            int totalResults,
            Long filterSince
    ) {
        this.prefix = prefix;
        this.hmacKey = hmacKey;
        this.hmacSource = hmacSource;
        this.timeWindow = timeWindow;
        this.totalResults = totalResults;
        this.filterSince = filterSince;
    }

    public String getPrefix() {
        return prefix;
    }

    public String getHmacKey() {
        return hmacKey;
    }

    public HmacSource getHmacSource() {
        return hmacSource;
    }

    public Long getTimeWindow() {
        return timeWindow;
    }

    public int getTotalResults() {
        return totalResults;
    }

    public Long getFilterSince() {
        return filterSince;
    }
}
