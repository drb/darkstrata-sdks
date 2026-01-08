// Package credentialcheck provides a privacy-first credential breach checking SDK
// using k-anonymity to protect user credentials.
package credentialcheck

import "time"

const (
	// Version is the SDK version
	Version = "1.0.0"

	// DefaultBaseURL is the default API endpoint
	DefaultBaseURL = "https://api.darkstrata.io/v1/"

	// DefaultTimeout is the default request timeout
	DefaultTimeout = 30 * time.Second

	// DefaultRetries is the default number of retry attempts
	DefaultRetries = 3

	// DefaultCacheTTL is the default cache time-to-live
	DefaultCacheTTL = 1 * time.Hour

	// PrefixLength is the number of characters used for k-anonymity prefix
	PrefixLength = 5

	// TimeWindowSeconds is the server HMAC key rotation interval
	TimeWindowSeconds = 3600

	// CredentialCheckEndpoint is the API endpoint for credential checks
	CredentialCheckEndpoint = "credential-check/query"

	// APIKeyHeader is the header name for API key authentication
	APIKeyHeader = "X-Api-Key"
)

// Response header names
const (
	HeaderPrefix       = "X-Prefix"
	HeaderHMACKey      = "X-HMAC-Key"
	HeaderHMACSource   = "X-HMAC-Source"
	HeaderTimeWindow   = "X-Time-Window"
	HeaderTotalResults = "X-Total-Results"
	HeaderFilterSince  = "X-Filter-Since"
)

// Retry configuration
const (
	RetryInitialDelay = 1 * time.Second
	RetryMaxDelay     = 10 * time.Second
	RetryBackoffBase  = 2.0
)

// RetryableStatusCodes are HTTP status codes that should trigger a retry
var RetryableStatusCodes = []int{408, 429, 500, 502, 503, 504}
