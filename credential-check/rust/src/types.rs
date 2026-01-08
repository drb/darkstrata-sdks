//! Types and structs for the DarkStrata Credential Check SDK.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration options for the DarkStrata client.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Required: API key (JWT token) for authentication.
    pub api_key: String,
    /// Base URL for the API. Defaults to `https://api.darkstrata.io/v1/`.
    pub base_url: Option<String>,
    /// Request timeout. Defaults to 30 seconds.
    pub timeout: Option<Duration>,
    /// Number of retry attempts for transient failures. Defaults to 3.
    pub retries: Option<u32>,
    /// Enable response caching. Defaults to true.
    pub enable_caching: Option<bool>,
    /// Cache time-to-live. Defaults to 1 hour.
    pub cache_ttl: Option<Duration>,
}

impl ClientOptions {
    /// Create new client options with the given API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: None,
            timeout: None,
            retries: None,
            enable_caching: None,
            cache_ttl: None,
        }
    }

    /// Set the base URL.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the number of retries.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = Some(retries);
        self
    }

    /// Enable or disable caching.
    pub fn enable_caching(mut self, enable: bool) -> Self {
        self.enable_caching = Some(enable);
        self
    }

    /// Set the cache TTL.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }
}

/// Resolved client configuration with defaults applied.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedConfig {
    pub api_key: String,
    pub base_url: String,
    pub timeout: Duration,
    pub retries: u32,
    pub enable_caching: bool,
    pub cache_ttl: Duration,
}

/// Options for individual check operations.
#[derive(Debug, Clone, Default)]
pub struct CheckOptions {
    /// Custom 256-bit HMAC key (64+ hex characters) for deterministic results.
    /// When provided, bypasses server-side HMAC rotation.
    pub client_hmac: Option<String>,
    /// Filter results to breaches since this date/time.
    /// Can be specified as epoch day (days since Unix epoch) or Unix timestamp.
    pub since: Option<SinceFilter>,
}

impl CheckOptions {
    /// Create new check options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom HMAC key.
    pub fn client_hmac(mut self, hmac: impl Into<String>) -> Self {
        self.client_hmac = Some(hmac.into());
        self
    }

    /// Filter by date using a DateTime.
    pub fn since_datetime(mut self, datetime: DateTime<Utc>) -> Self {
        self.since = Some(SinceFilter::DateTime(datetime));
        self
    }

    /// Filter by date using a NaiveDate.
    pub fn since_date(mut self, date: NaiveDate) -> Self {
        self.since = Some(SinceFilter::Date(date));
        self
    }

    /// Filter by epoch day (days since Unix epoch).
    pub fn since_epoch_day(mut self, epoch_day: u32) -> Self {
        self.since = Some(SinceFilter::EpochDay(epoch_day));
        self
    }

    /// Filter by Unix timestamp (seconds since Unix epoch).
    pub fn since_timestamp(mut self, timestamp: i64) -> Self {
        self.since = Some(SinceFilter::Timestamp(timestamp));
        self
    }
}

/// Filter for specifying a "since" date for breach results.
#[derive(Debug, Clone)]
pub enum SinceFilter {
    /// Filter by DateTime.
    DateTime(DateTime<Utc>),
    /// Filter by NaiveDate.
    Date(NaiveDate),
    /// Filter by epoch day (days since Unix epoch).
    EpochDay(u32),
    /// Filter by Unix timestamp (seconds since Unix epoch).
    Timestamp(i64),
}

impl SinceFilter {
    /// Convert the filter to an epoch day value for the API.
    pub fn to_epoch_day(&self) -> u32 {
        match self {
            SinceFilter::DateTime(dt) => (dt.timestamp() / 86400) as u32,
            SinceFilter::Date(date) => {
                let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
                date.signed_duration_since(epoch).num_days() as u32
            }
            SinceFilter::EpochDay(day) => *day,
            SinceFilter::Timestamp(ts) => (*ts / 86400) as u32,
        }
    }
}

/// A credential (email and password pair) to check.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The email address.
    pub email: String,
    /// The password.
    pub password: String,
}

impl Credential {
    /// Create a new credential.
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
        }
    }
}

/// Result of a credential check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Whether the credential was found in a data breach.
    pub found: bool,
    /// Information about the credential that was checked.
    pub credential: CredentialInfo,
    /// Metadata about the check operation.
    pub metadata: CheckMetadata,
}

/// Information about the checked credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    /// The email address that was checked.
    pub email: String,
    /// Always true - password is never included in results for security.
    pub masked: bool,
}

impl CredentialInfo {
    /// Create credential info for a checked email.
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            masked: true,
        }
    }

    /// Create masked credential info (for hash-only checks).
    pub fn masked() -> Self {
        Self {
            email: "[hash]".to_string(),
            masked: true,
        }
    }
}

/// Metadata about a check operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckMetadata {
    /// The 5-character hash prefix used for k-anonymity.
    pub prefix: String,
    /// Total number of matching hashes returned by the API.
    pub total_results: usize,
    /// Source of the HMAC key used.
    pub hmac_source: HmacSource,
    /// Server time window (only present when using server HMAC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<i64>,
    /// The epoch day filter that was applied (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_since: Option<u32>,
    /// Whether this result was served from cache.
    pub cached_result: bool,
    /// When the check was performed.
    pub checked_at: DateTime<Utc>,
}

/// Source of the HMAC key used for hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HmacSource {
    /// HMAC key provided by the server (rotates hourly).
    Server,
    /// HMAC key provided by the client (deterministic results).
    Client,
}

impl std::fmt::Display for HmacSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HmacSource::Server => write!(f, "server"),
            HmacSource::Client => write!(f, "client"),
        }
    }
}

impl std::str::FromStr for HmacSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "server" => Ok(HmacSource::Server),
            "client" => Ok(HmacSource::Client),
            _ => Err(format!("Invalid HMAC source: {}", s)),
        }
    }
}

/// Internal representation of API response.
#[derive(Debug, Clone)]
pub(crate) struct ApiResponse {
    /// List of HMAC'd hashes from the API.
    pub hashes: Vec<String>,
    /// The prefix that was queried.
    #[allow(dead_code)]
    pub prefix: String,
    /// The HMAC key used by the API.
    pub hmac_key: String,
    /// Source of the HMAC key.
    pub hmac_source: HmacSource,
    /// Server time window (if server HMAC).
    pub time_window: Option<i64>,
    /// Filter since epoch day (if applied).
    pub filter_since: Option<u32>,
}

/// Internal credential with pre-computed hash.
#[derive(Debug, Clone)]
pub(crate) struct HashedCredential {
    /// Original credential (if available).
    pub credential: Option<Credential>,
    /// SHA-256 hash of the credential.
    pub hash: String,
    /// First 5 characters of the hash (k-anonymity prefix).
    pub prefix: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_options_builder() {
        let options = ClientOptions::new("test-key")
            .base_url("https://custom.api.com/")
            .timeout(Duration::from_secs(60))
            .retries(5)
            .enable_caching(false)
            .cache_ttl(Duration::from_secs(1800));

        assert_eq!(options.api_key, "test-key");
        assert_eq!(
            options.base_url,
            Some("https://custom.api.com/".to_string())
        );
        assert_eq!(options.timeout, Some(Duration::from_secs(60)));
        assert_eq!(options.retries, Some(5));
        assert_eq!(options.enable_caching, Some(false));
        assert_eq!(options.cache_ttl, Some(Duration::from_secs(1800)));
    }

    #[test]
    fn test_check_options_builder() {
        let options = CheckOptions::new()
            .client_hmac("abc123")
            .since_epoch_day(19724);

        assert_eq!(options.client_hmac, Some("abc123".to_string()));
        assert!(matches!(options.since, Some(SinceFilter::EpochDay(19724))));
    }

    #[test]
    fn test_since_filter_to_epoch_day() {
        // Epoch day 0 = 1970-01-01
        let filter = SinceFilter::EpochDay(19723);
        assert_eq!(filter.to_epoch_day(), 19723);

        // Timestamp: 1704067200 = 2024-01-01 00:00:00 UTC
        // 1704067200 / 86400 = 19723 days since epoch
        let filter = SinceFilter::Timestamp(1704067200);
        assert_eq!(filter.to_epoch_day(), 19723);
    }

    #[test]
    fn test_hmac_source_parsing() {
        assert_eq!("server".parse::<HmacSource>().unwrap(), HmacSource::Server);
        assert_eq!("client".parse::<HmacSource>().unwrap(), HmacSource::Client);
        assert_eq!("SERVER".parse::<HmacSource>().unwrap(), HmacSource::Server);
        assert!("invalid".parse::<HmacSource>().is_err());
    }

    #[test]
    fn test_credential_info() {
        let info = CredentialInfo::new("test@example.com");
        assert_eq!(info.email, "test@example.com");
        assert!(info.masked);

        let masked = CredentialInfo::masked();
        assert_eq!(masked.email, "[hash]");
        assert!(masked.masked);
    }
}
