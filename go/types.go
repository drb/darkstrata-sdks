package credentialcheck

import (
	"time"
)

// ClientOptions configures the DarkStrata client
type ClientOptions struct {
	// APIKey is the JWT token for authentication (required)
	APIKey string

	// BaseURL is the API endpoint (default: https://api.darkstrata.io/v1/)
	BaseURL string

	// Timeout is the request timeout (default: 30s)
	Timeout time.Duration

	// Retries is the number of retry attempts (default: 3)
	Retries int

	// EnableCaching enables response caching (default: true)
	EnableCaching *bool

	// CacheTTL is the cache time-to-live (default: 1 hour)
	CacheTTL time.Duration
}

// Credential represents a single email/password pair
type Credential struct {
	Email    string
	Password string
}

// CheckOptions provides optional parameters for credential checks
type CheckOptions struct {
	// ClientHMAC is a custom HMAC key (64+ hex chars) for deterministic results
	ClientHMAC string

	// Since filters breaches to only those from this date onwards
	Since *time.Time
}

// CheckResult represents the result of a credential check
type CheckResult struct {
	// Found indicates if the credential was found in a breach
	Found bool

	// Credential contains masked credential info
	Credential CredentialInfo

	// Metadata contains additional result information
	Metadata CheckMetadata
}

// CredentialInfo contains masked credential information
type CredentialInfo struct {
	Email  string
	Masked bool
}

// CheckMetadata contains additional result information
type CheckMetadata struct {
	// Prefix is the 5-char hash prefix used
	Prefix string

	// TotalResults is the number of matching hashes returned
	TotalResults int

	// HMACSource indicates where the HMAC key came from ('server' or 'client')
	HMACSource string

	// TimeWindow is the server HMAC rotation window
	TimeWindow string

	// FilterSince is the epoch day filter value applied
	FilterSince int64

	// CachedResult indicates if this result came from cache
	CachedResult bool

	// CheckedAt is the timestamp of the check
	CheckedAt time.Time
}

// apiResponse represents the raw API response
type apiResponse struct {
	Hashes  []string
	Headers apiResponseHeaders
}

// apiResponseHeaders contains parsed response headers
type apiResponseHeaders struct {
	Prefix       string
	HMACKey      string
	HMACSource   string
	TimeWindow   string
	TotalResults int
	FilterSince  int64
}

// cacheEntry represents a cached API response
type cacheEntry struct {
	Response   apiResponse
	Timestamp  time.Time
	TimeWindow string
}

// resolvedConfig holds the fully resolved client configuration
type resolvedConfig struct {
	apiKey        string
	baseURL       string
	timeout       time.Duration
	retries       int
	enableCaching bool
	cacheTTL      time.Duration
}

// HashedCredential represents a credential with its precomputed hash
type HashedCredential struct {
	Email    string
	Password string
	Hash     string
}
