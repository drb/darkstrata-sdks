package credentialcheck

import (
	"errors"
	"testing"
	"time"
)

func TestDarkStrataError(t *testing.T) {
	err := &DarkStrataError{
		Code:      ErrCodeAPI,
		Message:   "test error",
		Retryable: true,
	}

	if err.Error() != "[API_ERROR] test error" {
		t.Errorf("Error() = %s, want [API_ERROR] test error", err.Error())
	}
}

func TestDarkStrataErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := &DarkStrataError{
		Code:      ErrCodeNetwork,
		Message:   "network failed",
		Retryable: true,
		Cause:     cause,
	}

	if err.Error() != "[NETWORK_ERROR] network failed: underlying error" {
		t.Errorf("Error() = %s", err.Error())
	}

	if err.Unwrap() != cause {
		t.Error("Unwrap() did not return cause")
	}
}

func TestAuthenticationError(t *testing.T) {
	err := NewAuthenticationError("invalid API key")

	if err.Code != ErrCodeAuthentication {
		t.Errorf("Code = %s, want %s", err.Code, ErrCodeAuthentication)
	}

	if err.Retryable {
		t.Error("Authentication errors should not be retryable")
	}
}

func TestValidationError(t *testing.T) {
	err := NewValidationError("email", "email is required")

	if err.Field != "email" {
		t.Errorf("Field = %s, want email", err.Field)
	}

	if err.Retryable {
		t.Error("Validation errors should not be retryable")
	}

	expected := "[VALIDATION_ERROR] email is required (field: email)"
	if err.Error() != expected {
		t.Errorf("Error() = %s, want %s", err.Error(), expected)
	}
}

func TestAPIError(t *testing.T) {
	// Test non-retryable status
	err := NewAPIError(400, "bad request", `{"error": "invalid"}`)

	if err.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", err.StatusCode)
	}

	if err.Retryable {
		t.Error("400 errors should not be retryable")
	}

	// Test retryable status
	err = NewAPIError(500, "server error", "")
	if !err.Retryable {
		t.Error("500 errors should be retryable")
	}
}

func TestTimeoutError(t *testing.T) {
	cause := errors.New("context deadline exceeded")
	err := NewTimeoutError("request timed out", cause)

	if !err.Retryable {
		t.Error("Timeout errors should be retryable")
	}

	if err.Cause != cause {
		t.Error("Cause not set correctly")
	}
}

func TestNetworkError(t *testing.T) {
	cause := errors.New("connection refused")
	err := NewNetworkError("failed to connect", cause)

	if !err.Retryable {
		t.Error("Network errors should be retryable")
	}

	if err.Cause != cause {
		t.Error("Cause not set correctly")
	}
}

func TestRateLimitError(t *testing.T) {
	err := NewRateLimitError("too many requests", 30*time.Second)

	if !err.Retryable {
		t.Error("Rate limit errors should be retryable")
	}

	if err.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", err.RetryAfter)
	}

	if err.Error() != "[RATE_LIMIT_ERROR] too many requests (retry after: 30s)" {
		t.Errorf("Error() = %s", err.Error())
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"AuthenticationError", NewAuthenticationError("bad key"), false},
		{"ValidationError", NewValidationError("field", "invalid"), false},
		{"APIError 400", NewAPIError(400, "bad request", ""), false},
		{"APIError 500", NewAPIError(500, "server error", ""), true},
		{"APIError 429", NewAPIError(429, "rate limit", ""), true},
		{"TimeoutError", NewTimeoutError("timeout", nil), true},
		{"NetworkError", NewNetworkError("network", nil), true},
		{"RateLimitError", NewRateLimitError("limit", 0), true},
		{"Other error", errors.New("random error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRetryable(tt.err)
			if got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDarkStrataError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"DarkStrataError", &DarkStrataError{}, true},
		{"AuthenticationError", NewAuthenticationError("bad key"), true},
		{"ValidationError", NewValidationError("field", "invalid"), true},
		{"APIError", NewAPIError(400, "bad request", ""), true},
		{"TimeoutError", NewTimeoutError("timeout", nil), true},
		{"NetworkError", NewNetworkError("network", nil), true},
		{"RateLimitError", NewRateLimitError("limit", 0), true},
		{"Standard error", errors.New("random error"), false},
		{"Nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDarkStrataError(tt.err)
			if got != tt.want {
				t.Errorf("IsDarkStrataError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetryableStatusCodes(t *testing.T) {
	retryable := []int{408, 429, 500, 502, 503, 504}
	nonRetryable := []int{400, 401, 403, 404, 405}

	for _, code := range retryable {
		if !isRetryableStatusCode(code) {
			t.Errorf("Status code %d should be retryable", code)
		}
	}

	for _, code := range nonRetryable {
		if isRetryableStatusCode(code) {
			t.Errorf("Status code %d should not be retryable", code)
		}
	}
}
