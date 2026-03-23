package io.darkstrata.credentialcheck.internal;

/**
 * Cache entry for storing API responses.
 */
public class CacheEntry {

    private final ApiResponse response;
    private final long timeWindow;
    private final long createdAt;

    public CacheEntry(ApiResponse response, long timeWindow) {
        this.response = response;
        this.timeWindow = timeWindow;
        this.createdAt = System.currentTimeMillis();
    }

    public ApiResponse getResponse() {
        return response;
    }

    public long getTimeWindow() {
        return timeWindow;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    /**
     * Check if this cache entry has expired.
     */
    public boolean isExpired(long currentTimeWindow, long cacheTTL) {
        if (timeWindow != currentTimeWindow) {
            return true;
        }
        return System.currentTimeMillis() - createdAt > cacheTTL;
    }
}
