//! Configuration constants for the DarkStrata Credential Check SDK.

use std::time::Duration;

/// Default base URL for the DarkStrata API.
pub const DEFAULT_BASE_URL: &str = "https://api.darkstrata.io/v1/";

/// Default request timeout (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of retry attempts.
pub const DEFAULT_RETRIES: u32 = 3;

/// Default cache TTL (1 hour).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Length of the k-anonymity prefix.
pub const PREFIX_LENGTH: usize = 5;

/// Server time window duration in seconds (1 hour).
pub const TIME_WINDOW_SECONDS: i64 = 3600;

/// The credential check API endpoint.
pub const CREDENTIAL_CHECK_ENDPOINT: &str = "credential-check/query";

/// HTTP header name for the API key.
pub const API_KEY_HEADER: &str = "X-Api-Key";

/// User-Agent header value.
pub const USER_AGENT: &str = concat!(
    "darkstrata-credential-check-rust/",
    env!("CARGO_PKG_VERSION")
);

/// Response header names.
pub mod response_headers {
    /// Header containing the hash prefix.
    pub const PREFIX: &str = "x-prefix";
    /// Header containing the HMAC key.
    pub const HMAC_KEY: &str = "x-hmac-key";
    /// Header indicating the HMAC source (server or client).
    pub const HMAC_SOURCE: &str = "x-hmac-source";
    /// Header containing the server time window.
    pub const TIME_WINDOW: &str = "x-time-window";
    /// Header containing the total number of results.
    pub const TOTAL_RESULTS: &str = "x-total-results";
    /// Header containing the filter since epoch day.
    pub const FILTER_SINCE: &str = "x-filter-since";
}

/// Retry policy configuration.
pub mod retry {
    use std::time::Duration;

    /// Initial delay before first retry.
    pub const INITIAL_DELAY: Duration = Duration::from_secs(1);
    /// Maximum delay between retries.
    pub const MAX_DELAY: Duration = Duration::from_secs(10);
    /// Backoff multiplier for exponential backoff.
    pub const BACKOFF_MULTIPLIER: u32 = 2;
}

/// Minimum length for a client HMAC key (256 bits = 64 hex characters).
pub const MIN_CLIENT_HMAC_LENGTH: usize = 64;

/// Expected length of a SHA-256 hash in hex (64 characters).
pub const SHA256_HEX_LENGTH: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
        assert_eq!(DEFAULT_RETRIES, 3);
        assert_eq!(DEFAULT_CACHE_TTL, Duration::from_secs(3600));
        assert_eq!(PREFIX_LENGTH, 5);
    }

    #[test]
    fn test_user_agent_format() {
        assert!(USER_AGENT.starts_with("darkstrata-credential-check-rust/"));
    }
}
