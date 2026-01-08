//! Error types for the DarkStrata Credential Check SDK.

use std::time::Duration;
use thiserror::Error;

/// Main error type for the DarkStrata SDK.
#[derive(Debug, Error)]
pub enum DarkStrataError {
    /// Authentication failed (invalid or missing API key).
    #[error("Authentication failed: {message}")]
    Authentication {
        /// Error message.
        message: String,
        /// HTTP status code (typically 401).
        status_code: Option<u16>,
    },

    /// Input validation failed.
    #[error("Validation error: {message}")]
    Validation {
        /// Error message describing the validation failure.
        message: String,
        /// The field that failed validation (if applicable).
        field: Option<String>,
    },

    /// API request failed.
    #[error("API error: {message}")]
    Api {
        /// Error message.
        message: String,
        /// HTTP status code.
        status_code: Option<u16>,
        /// Whether this error is retryable.
        retryable: bool,
    },

    /// Request timed out.
    #[error("Request timed out after {duration:?}")]
    Timeout {
        /// The timeout duration that was exceeded.
        duration: Duration,
    },

    /// Network connectivity error.
    #[error("Network error: {message}")]
    Network {
        /// Error message.
        message: String,
        /// The underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimit {
        /// Duration to wait before retrying (from Retry-After header).
        retry_after: Option<Duration>,
    },
}

impl DarkStrataError {
    /// Create an authentication error.
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
            status_code: Some(401),
        }
    }

    /// Create a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            field: None,
        }
    }

    /// Create a validation error for a specific field.
    pub fn validation_field(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create an API error.
    pub fn api(message: impl Into<String>, status_code: Option<u16>) -> Self {
        let retryable = status_code.is_some_and(is_retryable_status);
        Self::Api {
            message: message.into(),
            status_code,
            retryable,
        }
    }

    /// Create a timeout error.
    pub fn timeout(duration: Duration) -> Self {
        Self::Timeout { duration }
    }

    /// Create a network error.
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            source: None,
        }
    }

    /// Create a network error with a source.
    pub fn network_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Network {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a rate limit error.
    pub fn rate_limit(retry_after: Option<Duration>) -> Self {
        Self::RateLimit { retry_after }
    }

    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Authentication { .. } => false,
            Self::Validation { .. } => false,
            Self::Api { retryable, .. } => *retryable,
            Self::Timeout { .. } => true,
            Self::Network { .. } => true,
            Self::RateLimit { .. } => true,
        }
    }

    /// Get the HTTP status code if available.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Authentication { status_code, .. } => *status_code,
            Self::Validation { .. } => None,
            Self::Api { status_code, .. } => *status_code,
            Self::Timeout { .. } => None,
            Self::Network { .. } => None,
            Self::RateLimit { .. } => Some(429),
        }
    }

    /// Get the retry-after duration for rate limit errors.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimit { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// Result type alias for DarkStrata operations.
pub type Result<T> = std::result::Result<T, DarkStrataError>;

/// Check if an HTTP status code indicates a retryable error.
pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Convert a reqwest error to a DarkStrataError.
impl From<reqwest::Error> for DarkStrataError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            // Default timeout - actual duration not available from reqwest error
            Self::Timeout {
                duration: Duration::from_secs(30),
            }
        } else if err.is_connect() {
            Self::Network {
                message: format!("Connection failed: {}", err),
                source: Some(Box::new(err)),
            }
        } else if let Some(status) = err.status() {
            let status_code = status.as_u16();
            if status_code == 401 {
                Self::Authentication {
                    message: "Invalid or missing API key".to_string(),
                    status_code: Some(status_code),
                }
            } else if status_code == 429 {
                Self::RateLimit { retry_after: None }
            } else {
                Self::Api {
                    message: format!("Request failed: {}", err),
                    status_code: Some(status_code),
                    retryable: is_retryable_status(status_code),
                }
            }
        } else {
            Self::Network {
                message: format!("Request failed: {}", err),
                source: Some(Box::new(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_error() {
        let err = DarkStrataError::authentication("Invalid API key");
        assert!(!err.is_retryable());
        assert_eq!(err.status_code(), Some(401));
        assert!(err.to_string().contains("Invalid API key"));
    }

    #[test]
    fn test_validation_error() {
        let err = DarkStrataError::validation("Email is required");
        assert!(!err.is_retryable());
        assert_eq!(err.status_code(), None);
    }

    #[test]
    fn test_validation_field_error() {
        let err = DarkStrataError::validation_field("email", "Email is required");
        assert!(!err.is_retryable());
        if let DarkStrataError::Validation { field, .. } = err {
            assert_eq!(field, Some("email".to_string()));
        } else {
            panic!("Expected Validation error");
        }
    }

    #[test]
    fn test_api_error_retryable() {
        let err = DarkStrataError::api("Server error", Some(503));
        assert!(err.is_retryable());
        assert_eq!(err.status_code(), Some(503));
    }

    #[test]
    fn test_api_error_not_retryable() {
        let err = DarkStrataError::api("Bad request", Some(400));
        assert!(!err.is_retryable());
        assert_eq!(err.status_code(), Some(400));
    }

    #[test]
    fn test_timeout_error() {
        let err = DarkStrataError::timeout(Duration::from_secs(30));
        assert!(err.is_retryable());
        assert_eq!(err.status_code(), None);
    }

    #[test]
    fn test_network_error() {
        let err = DarkStrataError::network("Connection refused");
        assert!(err.is_retryable());
        assert_eq!(err.status_code(), None);
    }

    #[test]
    fn test_rate_limit_error() {
        let err = DarkStrataError::rate_limit(Some(Duration::from_secs(60)));
        assert!(err.is_retryable());
        assert_eq!(err.status_code(), Some(429));
        assert_eq!(err.retry_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_is_retryable_status() {
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(403));
        assert!(!is_retryable_status(404));
        assert!(is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(502));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(504));
    }
}
