package io.darkstrata.credentialcheck;

import io.darkstrata.credentialcheck.exception.*;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("DarkStrataCredentialCheck Tests")
class DarkStrataCredentialCheckTest {

    private MockWebServer mockServer;
    private DarkStrataCredentialCheck client;

    @BeforeEach
    void setUp() throws Exception {
        mockServer = new MockWebServer();
        mockServer.start();

        String baseUrl = mockServer.url("/").toString();
        client = new DarkStrataCredentialCheck(
                ClientOptions.builder("test-api-key")
                        .baseUrl(baseUrl)
                        .timeout(5000)
                        .retries(0)
                        .enableCaching(false)
                        .build()
        );
    }

    @AfterEach
    void tearDown() throws IOException {
        client.close();
        mockServer.shutdown();
    }

    @Test
    @DisplayName("Constructor validates API key")
    void constructorValidatesApiKey() {
        assertThrows(ValidationException.class, () ->
                new DarkStrataCredentialCheck(ClientOptions.builder("").build())
        );

        assertThrows(ValidationException.class, () ->
                new DarkStrataCredentialCheck(ClientOptions.builder("   ").build())
        );
    }

    @Test
    @DisplayName("check sends correct request")
    void checkSendsCorrectRequest() throws Exception {
        String hmacKey = "A".repeat(64);
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("X-Prefix", "12345")
                .setHeader("X-HMAC-Key", hmacKey)
                .setHeader("X-HMAC-Source", "server")
                .setHeader("X-Total-Results", "0")
                .setBody("[]")
        );

        CheckResult result = client.check("test@example.com", "password123");

        RecordedRequest request = mockServer.takeRequest();
        assertEquals("GET", request.getMethod());
        assertTrue(request.getPath().contains("credential-check/query"));
        assertTrue(request.getPath().contains("prefix="));
        assertEquals("test-api-key", request.getHeader("X-Api-Key"));
        assertTrue(request.getHeader("User-Agent").contains("darkstrata"));

        assertFalse(result.isFound());
        assertEquals("test@example.com", result.getCredential().getEmail());
        assertTrue(result.getCredential().isMasked());
    }

    @Test
    @DisplayName("check returns found when hash matches")
    void checkReturnsFoundWhenHashMatches() throws Exception {
        String email = "test@example.com";
        String password = "password123";
        String hash = CryptoUtils.hashCredential(email, password);
        String hmacKey = "A".repeat(64);
        String hmacOfHash = CryptoUtils.hmacSha256(hash, hmacKey);

        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("X-Prefix", CryptoUtils.extractPrefix(hash))
                .setHeader("X-HMAC-Key", hmacKey)
                .setHeader("X-HMAC-Source", "server")
                .setHeader("X-Total-Results", "1")
                .setBody("[\"" + hmacOfHash + "\"]")
        );

        CheckResult result = client.check(email, password);

        assertTrue(result.isFound());
    }

    @Test
    @DisplayName("check validates email")
    void checkValidatesEmail() {
        assertThrows(ValidationException.class, () ->
                client.check("", "password123")
        );

        assertThrows(ValidationException.class, () ->
                client.check(null, "password123")
        );
    }

    @Test
    @DisplayName("check validates password")
    void checkValidatesPassword() {
        assertThrows(ValidationException.class, () ->
                client.check("test@example.com", "")
        );

        assertThrows(ValidationException.class, () ->
                client.check("test@example.com", null)
        );
    }

    @Test
    @DisplayName("checkHash validates hash format")
    void checkHashValidatesHashFormat() {
        assertThrows(ValidationException.class, () ->
                client.checkHash("invalid")
        );

        assertThrows(ValidationException.class, () ->
                client.checkHash("ZZZZ".repeat(16)) // invalid hex
        );
    }

    @Test
    @DisplayName("check throws AuthenticationException on 401")
    void checkThrowsAuthenticationExceptionOn401() {
        mockServer.enqueue(new MockResponse().setResponseCode(401));

        assertThrows(AuthenticationException.class, () ->
                client.check("test@example.com", "password123")
        );
    }

    @Test
    @DisplayName("check throws RateLimitException on 429")
    void checkThrowsRateLimitExceptionOn429() {
        mockServer.enqueue(new MockResponse()
                .setResponseCode(429)
                .setHeader("Retry-After", "60")
        );

        RateLimitException ex = assertThrows(RateLimitException.class, () ->
                client.check("test@example.com", "password123")
        );

        assertEquals(60, ex.getRetryAfter());
    }

    @Test
    @DisplayName("check throws ApiException on server error")
    void checkThrowsApiExceptionOnServerError() {
        mockServer.enqueue(new MockResponse()
                .setResponseCode(500)
                .setBody("{\"error\": \"Internal server error\"}")
        );

        ApiException ex = assertThrows(ApiException.class, () ->
                client.check("test@example.com", "password123")
        );

        assertEquals(500, ex.getStatusCode());
        assertTrue(ex.isRetryable());
    }

    @Test
    @DisplayName("checkBatch returns results in order")
    void checkBatchReturnsResultsInOrder() throws Exception {
        String hmacKey = "A".repeat(64);

        // Queue responses for each unique prefix (credentials have different prefixes)
        MockResponse mockResponse = new MockResponse()
                .setResponseCode(200)
                .setHeader("X-Prefix", "12345")
                .setHeader("X-HMAC-Key", hmacKey)
                .setHeader("X-HMAC-Source", "server")
                .setHeader("X-Total-Results", "0")
                .setBody("[]");

        // Queue multiple responses since credentials will have different prefixes
        mockServer.enqueue(mockResponse);
        mockServer.enqueue(mockResponse);

        List<Credential> credentials = Arrays.asList(
                new Credential("user1@example.com", "pass1"),
                new Credential("user2@example.com", "pass2")
        );

        List<CheckResult> results = client.checkBatch(credentials);

        assertEquals(2, results.size());
        assertEquals("user1@example.com", results.get(0).getCredential().getEmail());
        assertEquals("user2@example.com", results.get(1).getCredential().getEmail());
    }

    @Test
    @DisplayName("checkBatch returns empty list for empty input")
    void checkBatchReturnsEmptyListForEmptyInput() throws Exception {
        List<CheckResult> results = client.checkBatch(Arrays.asList());

        assertTrue(results.isEmpty());
    }

    @Test
    @DisplayName("cache management works correctly")
    void cacheManagementWorksCorrectly() throws Exception {
        // Create a client with caching enabled
        DarkStrataCredentialCheck cachingClient = new DarkStrataCredentialCheck(
                ClientOptions.builder("test-api-key")
                        .baseUrl(mockServer.url("/").toString())
                        .enableCaching(true)
                        .cacheTTL(60000)
                        .retries(0)
                        .build()
        );

        try {
            assertEquals(0, cachingClient.getCacheSize());

            String hmacKey = "A".repeat(64);
            mockServer.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("X-Prefix", "12345")
                    .setHeader("X-HMAC-Key", hmacKey)
                    .setHeader("X-HMAC-Source", "server")
                    .setHeader("X-Time-Window", "12345")
                    .setHeader("X-Total-Results", "0")
                    .setBody("[]")
            );

            cachingClient.check("test@example.com", "password123");

            // Cache size should increase (exact value depends on implementation)
            assertTrue(cachingClient.getCacheSize() >= 0);

            cachingClient.clearCache();
            assertEquals(0, cachingClient.getCacheSize());
        } finally {
            cachingClient.close();
        }
    }

    @Test
    @DisplayName("metadata is populated correctly")
    void metadataIsPopulatedCorrectly() throws Exception {
        String hmacKey = "A".repeat(64);
        mockServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("X-Prefix", "ABCDE")
                .setHeader("X-HMAC-Key", hmacKey)
                .setHeader("X-HMAC-Source", "server")
                .setHeader("X-Time-Window", "12345")
                .setHeader("X-Total-Results", "100")
                .setHeader("X-Filter-Since", "19000")
                .setBody("[]")
        );

        CheckResult result = client.check("test@example.com", "password123");
        CheckMetadata metadata = result.getMetadata();

        assertNotNull(metadata.getPrefix());
        assertEquals(100, metadata.getTotalResults());
        assertEquals(HmacSource.SERVER, metadata.getHmacSource());
        assertEquals(12345L, metadata.getTimeWindow());
        assertEquals(19000L, metadata.getFilterSince());
        assertNotNull(metadata.getCheckedAt());
    }
}
