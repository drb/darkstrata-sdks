package credentialcheck

import (
	"fmt"
	"time"
)

// ErrorCode represents the type of error that occurred
type ErrorCode string

const (
	ErrCodeAuthentication ErrorCode = "AUTHENTICATION_ERROR"
	ErrCodeValidation     ErrorCode = "VALIDATION_ERROR"
	ErrCodeAPI            ErrorCode = "API_ERROR"
	ErrCodeTimeout        ErrorCode = "TIMEOUT_ERROR"
	ErrCodeNetwork        ErrorCode = "NETWORK_ERROR"
	ErrCodeRateLimit      ErrorCode = "RATE_LIMIT_ERROR"
)

// DarkStrataError is the base error type for all SDK errors
type DarkStrataError struct {
	Code      ErrorCode
	Message   string
	Retryable bool
	Cause     error
}

func (e *DarkStrataError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *DarkStrataError) Unwrap() error {
	return e.Cause
}

// AuthenticationError represents authentication failures (401)
type AuthenticationError struct {
	DarkStrataError
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string) *AuthenticationError {
	return &AuthenticationError{
		DarkStrataError: DarkStrataError{
			Code:      ErrCodeAuthentication,
			Message:   message,
			Retryable: false,
		},
	}
}

// ValidationError represents validation failures
type ValidationError struct {
	DarkStrataError
	Field string
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		DarkStrataError: DarkStrataError{
			Code:      ErrCodeValidation,
			Message:   message,
			Retryable: false,
		},
		Field: field,
	}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("[%s] %s (field: %s)", e.Code, e.Message, e.Field)
}

// APIError represents API response errors
type APIError struct {
	DarkStrataError
	StatusCode   int
	ResponseBody string
}

// NewAPIError creates a new API error
func NewAPIError(statusCode int, message, responseBody string) *APIError {
	return &APIError{
		DarkStrataError: DarkStrataError{
			Code:      ErrCodeAPI,
			Message:   message,
			Retryable: isRetryableStatusCode(statusCode),
		},
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("[%s] %s (status: %d)", e.Code, e.Message, e.StatusCode)
}

// TimeoutError represents request timeout errors
type TimeoutError struct {
	DarkStrataError
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(message string, cause error) *TimeoutError {
	return &TimeoutError{
		DarkStrataError: DarkStrataError{
			Code:      ErrCodeTimeout,
			Message:   message,
			Retryable: true,
			Cause:     cause,
		},
	}
}

// NetworkError represents network connectivity errors
type NetworkError struct {
	DarkStrataError
}

// NewNetworkError creates a new network error
func NewNetworkError(message string, cause error) *NetworkError {
	return &NetworkError{
		DarkStrataError: DarkStrataError{
			Code:      ErrCodeNetwork,
			Message:   message,
			Retryable: true,
			Cause:     cause,
		},
	}
}

// RateLimitError represents rate limiting (429) errors
type RateLimitError struct {
	DarkStrataError
	RetryAfter time.Duration
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(message string, retryAfter time.Duration) *RateLimitError {
	return &RateLimitError{
		DarkStrataError: DarkStrataError{
			Code:      ErrCodeRateLimit,
			Message:   message,
			Retryable: true,
		},
		RetryAfter: retryAfter,
	}
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("[%s] %s (retry after: %v)", e.Code, e.Message, e.RetryAfter)
}

// IsRetryable returns true if the error is retryable
func IsRetryable(err error) bool {
	if dsErr, ok := err.(*DarkStrataError); ok {
		return dsErr.Retryable
	}
	if authErr, ok := err.(*AuthenticationError); ok {
		return authErr.Retryable
	}
	if valErr, ok := err.(*ValidationError); ok {
		return valErr.Retryable
	}
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Retryable
	}
	if toErr, ok := err.(*TimeoutError); ok {
		return toErr.Retryable
	}
	if netErr, ok := err.(*NetworkError); ok {
		return netErr.Retryable
	}
	if rlErr, ok := err.(*RateLimitError); ok {
		return rlErr.Retryable
	}
	return false
}

// IsDarkStrataError returns true if the error is a DarkStrata SDK error
func IsDarkStrataError(err error) bool {
	switch err.(type) {
	case *DarkStrataError, *AuthenticationError, *ValidationError,
		*APIError, *TimeoutError, *NetworkError, *RateLimitError:
		return true
	default:
		return false
	}
}

func isRetryableStatusCode(code int) bool {
	for _, c := range RetryableStatusCodes {
		if c == code {
			return true
		}
	}
	return false
}
