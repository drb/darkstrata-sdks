package io.darkstrata.credentialcheck.internal;

import java.util.List;

/**
 * Internal representation of an API response.
 */
public class ApiResponse {

    private final List<String> hashes;
    private final ApiResponseHeaders headers;

    public ApiResponse(List<String> hashes, ApiResponseHeaders headers) {
        this.hashes = hashes;
        this.headers = headers;
    }

    public List<String> getHashes() {
        return hashes;
    }

    public ApiResponseHeaders getHeaders() {
        return headers;
    }
}
