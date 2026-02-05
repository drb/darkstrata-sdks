package credentialcheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Test valid client creation
	client, err := NewClient(ClientOptions{
		APIKey: "test-api-key",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}

	// Test missing API key
	_, err = NewClient(ClientOptions{})
	if err == nil {
		t.Error("NewClient() should error without API key")
	}
	if valErr, ok := err.(*ValidationError); !ok || valErr.Field != "apiKey" {
		t.Errorf("Expected ValidationError for apiKey, got %v", err)
	}
}

func TestNewClientWithOptions(t *testing.T) {
	enableCaching := false
	client, err := NewClient(ClientOptions{
		APIKey:        "test-key",
		BaseURL:       "https://custom.api/v1/",
		Timeout:       10 * time.Second,
		Retries:       5,
		EnableCaching: &enableCaching,
		CacheTTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.config.baseURL != "https://custom.api/v1/" {
		t.Errorf("baseURL = %s, want https://custom.api/v1/", client.config.baseURL)
	}
	if client.config.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", client.config.timeout)
	}
	if client.config.retries != 5 {
		t.Errorf("retries = %d, want 5", client.config.retries)
	}
	if client.config.enableCaching {
		t.Error("enableCaching should be false")
	}
	if client.config.cacheTTL != 30*time.Minute {
		t.Errorf("cacheTTL = %v, want 30m", client.config.cacheTTL)
	}
}

func TestCheckValidation(t *testing.T) {
	client, _ := NewClient(ClientOptions{APIKey: "test-key"})
	ctx := context.Background()

	// Test empty email
	_, err := client.Check(ctx, "", "password", nil)
	if err == nil {
		t.Error("Check() should error with empty email")
	}

	// Test empty password
	_, err = client.Check(ctx, "email@test.com", "", nil)
	if err == nil {
		t.Error("Check() should error with empty password")
	}
}

func TestCheckHashValidation(t *testing.T) {
	client, _ := NewClient(ClientOptions{APIKey: "test-key"})
	ctx := context.Background()

	// Test invalid hash
	_, err := client.CheckHash(ctx, "invalid", nil)
	if err == nil {
		t.Error("CheckHash() should error with invalid hash")
	}

	// Test short hash
	_, err = client.CheckHash(ctx, "abcde", nil)
	if err == nil {
		t.Error("CheckHash() should error with short hash")
	}
}

func TestCheckBatchValidation(t *testing.T) {
	client, _ := NewClient(ClientOptions{APIKey: "test-key"})
	ctx := context.Background()

	// Test empty credentials
	results, err := client.CheckBatch(ctx, []Credential{}, nil)
	if err != nil {
		t.Errorf("CheckBatch() with empty slice should not error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("CheckBatch() with empty slice should return empty results")
	}

	// Test invalid credential in batch
	_, err = client.CheckBatch(ctx, []Credential{
		{Email: "valid@test.com", Password: "pass"},
		{Email: "", Password: "pass"}, // Invalid
	}, nil)
	if err == nil {
		t.Error("CheckBatch() should error with invalid credential")
	}
}

func TestCacheOperations(t *testing.T) {
	client, _ := NewClient(ClientOptions{APIKey: "test-key"})

	if client.GetCacheSize() != 0 {
		t.Error("New client should have empty cache")
	}

	// Manually add a cache entry for testing
	client.cacheMu.Lock()
	client.cache["test-key"] = cacheEntry{
		Response:  apiResponse{Hashes: []string{}},
		Timestamp: time.Now(),
	}
	client.cacheMu.Unlock()

	if client.GetCacheSize() != 1 {
		t.Errorf("Cache size = %d, want 1", client.GetCacheSize())
	}

	client.ClearCache()

	if client.GetCacheSize() != 0 {
		t.Error("Cache should be empty after clear")
	}
}

func TestMockAPICheck(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "GET" {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		if r.Header.Get(APIKeyHeader) != "test-api-key" {
			t.Error("API key not sent")
		}

		prefix := r.URL.Query().Get("prefix")
		if len(prefix) != 5 {
			t.Errorf("Prefix length = %d, want 5", len(prefix))
		}

		// Set response headers
		w.Header().Set(HeaderPrefix, prefix)
		w.Header().Set(HeaderHMACKey, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		w.Header().Set(HeaderHMACSource, "server")
		w.Header().Set(HeaderTimeWindow, "12345")
		w.Header().Set(HeaderTotalResults, "100")

		// Return empty hash list (not found)
		json.NewEncoder(w).Encode([]string{})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test-api-key",
		BaseURL: server.URL + "/",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	result, err := client.Check(context.Background(), "test@example.com", "password123", nil)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if result.Found {
		t.Error("Check() found = true, want false")
	}
	if result.Metadata.HMACSource != "server" {
		t.Errorf("HMACSource = %s, want server", result.Metadata.HMACSource)
	}
	if result.Metadata.TotalResults != 100 {
		t.Errorf("TotalResults = %d, want 100", result.Metadata.TotalResults)
	}
}

func TestMockAPICheckFound(t *testing.T) {
	testEmail := "test@example.com"
	testPassword := "password123"
	testHash := HashCredential(testEmail, testPassword)
	hmacKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Compute expected HMAC
	expectedHMAC, _ := HMACSHA256(testHash, hmacKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderPrefix, ExtractPrefix(testHash))
		w.Header().Set(HeaderHMACKey, hmacKey)
		w.Header().Set(HeaderHMACSource, "server")
		w.Header().Set(HeaderTotalResults, "1")

		// Return matching hash
		json.NewEncoder(w).Encode([]string{expectedHMAC})
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
	})

	result, err := client.Check(context.Background(), testEmail, testPassword, nil)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if !result.Found {
		t.Error("Check() found = false, want true")
	}
}

func TestMockAPIAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid api key"}`))
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "bad-key",
		BaseURL: server.URL + "/",
		Retries: 0, // No retries for faster test
	})

	_, err := client.Check(context.Background(), "test@example.com", "password", nil)
	if err == nil {
		t.Fatal("Check() should error with 401")
	}

	authErr, ok := err.(*AuthenticationError)
	if !ok {
		t.Errorf("Expected AuthenticationError, got %T", err)
	}
	if authErr.Retryable {
		t.Error("AuthenticationError should not be retryable")
	}
}

func TestMockAPIRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "rate limited"}`))
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
		Retries: 0,
	})

	_, err := client.Check(context.Background(), "test@example.com", "password", nil)
	if err == nil {
		t.Fatal("Check() should error with 429")
	}

	rlErr, ok := err.(*RateLimitError)
	if !ok {
		t.Errorf("Expected RateLimitError, got %T", err)
	}
	if rlErr.RetryAfter != 60*time.Second {
		t.Errorf("RetryAfter = %v, want 60s", rlErr.RetryAfter)
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Slow response
		json.NewEncoder(w).Encode([]string{})
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
		Timeout: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Check(ctx, "test@example.com", "password", nil)
	if err == nil {
		t.Fatal("Check() should error with cancelled context")
	}
}

func TestCheckWithOptions(t *testing.T) {
	var capturedQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery

		w.Header().Set(HeaderHMACKey, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		json.NewEncoder(w).Encode([]string{})
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
	})

	since := time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC)
	_, err := client.Check(context.Background(), "test@example.com", "password", &CheckOptions{
		ClientHMAC: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Since:      &since,
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	// Verify query parameters
	if capturedQuery == "" {
		t.Error("Query should contain parameters")
	}
	// Should contain clientHmac and since parameters
}

func TestBuildCacheKey(t *testing.T) {
	client, _ := NewClient(ClientOptions{APIKey: "test"})

	// Simple key
	key := client.buildCacheKey("abcde", nil)
	if key != "abcde" {
		t.Errorf("Cache key = %s, want abcde", key)
	}

	// Key with options
	since := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	key = client.buildCacheKey("abcde", &CheckOptions{
		ClientHMAC: "myhexkey",
		Since:      &since,
	})
	if key == "abcde" {
		t.Error("Cache key should include options")
	}
}

func TestCacheValidation(t *testing.T) {
	client, _ := NewClient(ClientOptions{
		APIKey:   "test",
		CacheTTL: 1 * time.Second,
	})

	// Valid entry
	entry := cacheEntry{
		Timestamp:  time.Now(),
		TimeWindow: "",
	}
	if !client.isCacheValid(entry) {
		t.Error("Fresh entry should be valid")
	}

	// Expired entry
	entry.Timestamp = time.Now().Add(-2 * time.Second)
	if client.isCacheValid(entry) {
		t.Error("Expired entry should be invalid")
	}
}

func TestMockAPICheckHash(t *testing.T) {
	testEmail := "test@example.com"
	testPassword := "password123"
	testHash := HashCredential(testEmail, testPassword)
	hmacKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	expectedHMAC, _ := HMACSHA256(testHash, hmacKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify prefix parameter
		prefix := r.URL.Query().Get("prefix")
		if len(prefix) != 5 {
			t.Errorf("Prefix length = %d, want 5", len(prefix))
		}

		w.Header().Set(HeaderPrefix, prefix)
		w.Header().Set(HeaderHMACKey, hmacKey)
		w.Header().Set(HeaderHMACSource, "server")
		w.Header().Set(HeaderTotalResults, "1")

		json.NewEncoder(w).Encode([]string{expectedHMAC})
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
	})

	result, err := client.CheckHash(context.Background(), testHash, nil)
	if err != nil {
		t.Fatalf("CheckHash() error = %v", err)
	}

	if !result.Found {
		t.Error("CheckHash() found = false, want true")
	}
	if result.Credential.Email != "" {
		t.Errorf("CheckHash() email = %q, want empty", result.Credential.Email)
	}
}

func TestMockAPICheckBatch(t *testing.T) {
	hmacKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	credentials := []Credential{
		{Email: "user1@example.com", Password: "pass1"},
		{Email: "user2@example.com", Password: "pass2"},
	}

	// Precompute hash for user1 so we can mark it as found
	user1Hash := HashCredential("user1@example.com", "pass1")
	user1HMAC, _ := HMACSHA256(user1Hash, hmacKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Query().Get("prefix")

		w.Header().Set(HeaderPrefix, prefix)
		w.Header().Set(HeaderHMACKey, hmacKey)
		w.Header().Set(HeaderHMACSource, "server")
		w.Header().Set(HeaderTotalResults, "1")

		// Return user1's HMAC in every prefix response so user1 is found
		json.NewEncoder(w).Encode([]string{user1HMAC})
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
	})

	results, err := client.CheckBatch(context.Background(), credentials, nil)
	if err != nil {
		t.Fatalf("CheckBatch() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("CheckBatch() returned %d results, want 2", len(results))
	}

	// user1 should be found
	if !results[0].Found {
		t.Error("CheckBatch() user1 found = false, want true")
	}
	if results[0].Credential.Email != "user1@example.com" {
		t.Errorf("CheckBatch() user1 email = %q, want user1@example.com", results[0].Credential.Email)
	}

	// user2 should not be found (different hash)
	if results[1].Found {
		t.Error("CheckBatch() user2 found = true, want false")
	}
	if results[1].Credential.Email != "user2@example.com" {
		t.Errorf("CheckBatch() user2 email = %q, want user2@example.com", results[1].Credential.Email)
	}
}

func TestMockAPIServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client, _ := NewClient(ClientOptions{
		APIKey:  "test-key",
		BaseURL: server.URL + "/",
		Retries: 0,
	})

	_, err := client.Check(context.Background(), "test@example.com", "password", nil)
	if err == nil {
		t.Fatal("Check() should error with 500")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Errorf("Expected APIError, got %T: %v", err, err)
	} else {
		if apiErr.StatusCode != 500 {
			t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
		}
		if !apiErr.Retryable {
			t.Error("500 error should be retryable")
		}
	}
}
