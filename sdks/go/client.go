package credentialcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is the DarkStrata credential check client
type Client struct {
	config     resolvedConfig
	httpClient *http.Client
	cache      map[string]cacheEntry
	cacheMu    sync.RWMutex
}

// NewClient creates a new DarkStrata credential check client
func NewClient(options ClientOptions) (*Client, error) {
	config, err := resolveConfig(options)
	if err != nil {
		return nil, err
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.timeout,
		},
		cache: make(map[string]cacheEntry),
	}, nil
}

// Check verifies if a credential has been exposed in data breaches
func (c *Client) Check(ctx context.Context, email, password string, opts *CheckOptions) (*CheckResult, error) {
	if email == "" {
		return nil, NewValidationError("email", "email is required")
	}
	if password == "" {
		return nil, NewValidationError("password", "password is required")
	}

	hash := HashCredential(email, password)
	return c.checkWithHash(ctx, email, hash, opts)
}

// CheckHash verifies if a precomputed hash has been exposed in data breaches
func (c *Client) CheckHash(ctx context.Context, hash string, opts *CheckOptions) (*CheckResult, error) {
	if !IsValidHash(hash, 64) {
		return nil, NewValidationError("hash", "invalid SHA-256 hash format (expected 64 hex characters)")
	}

	return c.checkWithHash(ctx, "", hash, opts)
}

// CheckBatch checks multiple credentials efficiently by grouping by prefix
func (c *Client) CheckBatch(ctx context.Context, credentials []Credential, opts *CheckOptions) ([]CheckResult, error) {
	if len(credentials) == 0 {
		return []CheckResult{}, nil
	}

	// Validate and hash all credentials
	hashedCreds := make([]HashedCredential, 0, len(credentials))
	for i, cred := range credentials {
		if cred.Email == "" {
			return nil, NewValidationError(fmt.Sprintf("credentials[%d].email", i), "email is required")
		}
		if cred.Password == "" {
			return nil, NewValidationError(fmt.Sprintf("credentials[%d].password", i), "password is required")
		}
		hashedCreds = append(hashedCreds, HashedCredential{
			Email:    cred.Email,
			Password: cred.Password,
			Hash:     HashCredential(cred.Email, cred.Password),
		})
	}

	// Group by prefix for efficient batching
	groups := GroupByPrefix(hashedCreds, func(hc HashedCredential) string {
		return hc.Hash
	})

	// Process each prefix group
	results := make([]CheckResult, len(credentials))
	resultIndex := make(map[string]int)
	for i, hc := range hashedCreds {
		resultIndex[hc.Hash] = i
	}

	for prefix, group := range groups {
		// Fetch API response for this prefix (uses cache if available)
		response, cached, err := c.fetchWithCache(ctx, prefix, opts)
		if err != nil {
			return nil, err
		}

		// Check each credential in this group
		for _, hc := range group {
			found, err := IsHashInSet(hc.Hash, response.Headers.HMACKey, response.Hashes)
			if err != nil {
				return nil, err
			}

			idx := resultIndex[hc.Hash]
			results[idx] = CheckResult{
				Found: found,
				Credential: CredentialInfo{
					Email:  hc.Email,
					Masked: true,
				},
				Metadata: CheckMetadata{
					Prefix:       response.Headers.Prefix,
					TotalResults: response.Headers.TotalResults,
					HMACSource:   response.Headers.HMACSource,
					TimeWindow:   response.Headers.TimeWindow,
					FilterSince:  response.Headers.FilterSince,
					CachedResult: cached,
					CheckedAt:    time.Now(),
				},
			}
		}
	}

	return results, nil
}

// ClearCache clears the internal response cache
func (c *Client) ClearCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = make(map[string]cacheEntry)
}

// GetCacheSize returns the number of entries in the cache
func (c *Client) GetCacheSize() int {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	return len(c.cache)
}

// checkWithHash performs the actual credential check
func (c *Client) checkWithHash(ctx context.Context, email, hash string, opts *CheckOptions) (*CheckResult, error) {
	prefix := ExtractPrefix(hash)

	response, cached, err := c.fetchWithCache(ctx, prefix, opts)
	if err != nil {
		return nil, err
	}

	found, err := IsHashInSet(hash, response.Headers.HMACKey, response.Hashes)
	if err != nil {
		return nil, err
	}

	return &CheckResult{
		Found: found,
		Credential: CredentialInfo{
			Email:  email,
			Masked: true,
		},
		Metadata: CheckMetadata{
			Prefix:       response.Headers.Prefix,
			TotalResults: response.Headers.TotalResults,
			HMACSource:   response.Headers.HMACSource,
			TimeWindow:   response.Headers.TimeWindow,
			FilterSince:  response.Headers.FilterSince,
			CachedResult: cached,
			CheckedAt:    time.Now(),
		},
	}, nil
}

// fetchWithCache retrieves from cache or fetches from API
func (c *Client) fetchWithCache(ctx context.Context, prefix string, opts *CheckOptions) (*apiResponse, bool, error) {
	if !c.config.enableCaching {
		response, err := c.fetchWithRetry(ctx, prefix, opts)
		return response, false, err
	}

	cacheKey := c.buildCacheKey(prefix, opts)

	// Check cache
	c.cacheMu.RLock()
	entry, exists := c.cache[cacheKey]
	c.cacheMu.RUnlock()

	if exists && c.isCacheValid(entry) {
		return &entry.Response, true, nil
	}

	// Fetch from API
	response, err := c.fetchWithRetry(ctx, prefix, opts)
	if err != nil {
		return nil, false, err
	}

	// Store in cache
	c.cacheMu.Lock()
	c.cache[cacheKey] = cacheEntry{
		Response:   *response,
		Timestamp:  time.Now(),
		TimeWindow: response.Headers.TimeWindow,
	}
	c.cacheMu.Unlock()

	return response, false, nil
}

// fetchWithRetry performs the API request with retry logic
func (c *Client) fetchWithRetry(ctx context.Context, prefix string, opts *CheckOptions) (*apiResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= c.config.retries; attempt++ {
		if attempt > 0 {
			delay := c.calculateBackoff(attempt)
			select {
			case <-ctx.Done():
				return nil, NewTimeoutError("request cancelled", ctx.Err())
			case <-time.After(delay):
			}
		}

		response, err := c.doRequest(ctx, prefix, opts)
		if err == nil {
			return response, nil
		}

		lastErr = err

		// Don't retry non-retryable errors
		if !IsRetryable(err) {
			return nil, err
		}
	}

	return nil, lastErr
}

// doRequest performs a single API request
func (c *Client) doRequest(ctx context.Context, prefix string, opts *CheckOptions) (*apiResponse, error) {
	// Build URL
	endpoint := strings.TrimSuffix(c.config.baseURL, "/") + "/" + CredentialCheckEndpoint
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, NewValidationError("baseURL", "invalid base URL")
	}

	q := u.Query()
	q.Set("prefix", prefix)

	if opts != nil {
		if opts.ClientHMAC != "" {
			if len(opts.ClientHMAC) < 64 || !IsValidHash(opts.ClientHMAC, len(opts.ClientHMAC)) {
				return nil, NewValidationError("clientHMAC", "clientHMAC must be at least 64 hex characters")
			}
			q.Set("clientHmac", opts.ClientHMAC)
		}
		if opts.Since != nil {
			// Convert to epoch days
			epochDays := opts.Since.Unix() / 86400
			q.Set("since", strconv.FormatInt(epochDays, 10))
		}
	}
	u.RawQuery = q.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, NewNetworkError("failed to create request", err)
	}

	req.Header.Set(APIKeyHeader, c.config.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("darkstrata-go/%s", Version))

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewTimeoutError("request timed out", err)
		}
		return nil, NewNetworkError("request failed", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewNetworkError("failed to read response", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.StatusCode, string(body), resp.Header)
	}

	// Parse response
	var hashes []string
	if err := json.Unmarshal(body, &hashes); err != nil {
		return nil, NewAPIError(resp.StatusCode, "failed to parse response", string(body))
	}

	// Parse headers
	headers := c.parseResponseHeaders(resp.Header)

	return &apiResponse{
		Hashes:  hashes,
		Headers: headers,
	}, nil
}

// handleErrorResponse converts HTTP errors to SDK errors
func (c *Client) handleErrorResponse(statusCode int, body string, headers http.Header) error {
	switch statusCode {
	case http.StatusUnauthorized:
		return NewAuthenticationError("invalid or expired API key")
	case http.StatusTooManyRequests:
		retryAfter := time.Duration(0)
		if ra := headers.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil {
				retryAfter = time.Duration(seconds) * time.Second
			}
		}
		return NewRateLimitError("rate limit exceeded", retryAfter)
	default:
		return NewAPIError(statusCode, fmt.Sprintf("API request failed with status %d", statusCode), body)
	}
}

// parseResponseHeaders extracts relevant headers from the response
func (c *Client) parseResponseHeaders(headers http.Header) apiResponseHeaders {
	result := apiResponseHeaders{
		Prefix:     headers.Get(HeaderPrefix),
		HMACKey:    headers.Get(HeaderHMACKey),
		HMACSource: headers.Get(HeaderHMACSource),
		TimeWindow: headers.Get(HeaderTimeWindow),
	}

	if tr := headers.Get(HeaderTotalResults); tr != "" {
		if n, err := strconv.Atoi(tr); err == nil {
			result.TotalResults = n
		}
	}

	if fs := headers.Get(HeaderFilterSince); fs != "" {
		if n, err := strconv.ParseInt(fs, 10, 64); err == nil {
			result.FilterSince = n
		}
	}

	return result
}

// calculateBackoff returns the delay for exponential backoff
func (c *Client) calculateBackoff(attempt int) time.Duration {
	delay := float64(RetryInitialDelay) * math.Pow(RetryBackoffBase, float64(attempt-1))
	if delay > float64(RetryMaxDelay) {
		delay = float64(RetryMaxDelay)
	}
	return time.Duration(delay)
}

// buildCacheKey creates a unique cache key for the request
func (c *Client) buildCacheKey(prefix string, opts *CheckOptions) string {
	key := prefix
	if opts != nil {
		if opts.ClientHMAC != "" {
			key += "|hmac:" + opts.ClientHMAC
		}
		if opts.Since != nil {
			key += "|since:" + strconv.FormatInt(opts.Since.Unix()/86400, 10)
		}
	}
	return key
}

// isCacheValid checks if a cache entry is still valid
func (c *Client) isCacheValid(entry cacheEntry) bool {
	// Check TTL
	if time.Since(entry.Timestamp) > c.config.cacheTTL {
		return false
	}

	// Check time window (server HMAC key rotation)
	if entry.TimeWindow != "" {
		currentWindow := strconv.FormatInt(time.Now().Unix()/TimeWindowSeconds, 10)
		if entry.TimeWindow != currentWindow {
			return false
		}
	}

	return true
}

// resolveConfig validates and resolves configuration options
func resolveConfig(options ClientOptions) (resolvedConfig, error) {
	if options.APIKey == "" {
		return resolvedConfig{}, NewValidationError("apiKey", "API key is required")
	}

	config := resolvedConfig{
		apiKey:        options.APIKey,
		baseURL:       DefaultBaseURL,
		timeout:       DefaultTimeout,
		retries:       DefaultRetries,
		enableCaching: true,
		cacheTTL:      DefaultCacheTTL,
	}

	if options.BaseURL != "" {
		config.baseURL = options.BaseURL
	}

	if options.Timeout > 0 {
		config.timeout = options.Timeout
	}

	if options.Retries >= 0 {
		config.retries = options.Retries
	}

	if options.EnableCaching != nil {
		config.enableCaching = *options.EnableCaching
	}

	if options.CacheTTL > 0 {
		config.cacheTTL = options.CacheTTL
	}

	return config, nil
}
