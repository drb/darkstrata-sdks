//! Main client implementation for the DarkStrata Credential Check SDK.

use crate::constants::{
    response_headers, retry, API_KEY_HEADER, CREDENTIAL_CHECK_ENDPOINT, DEFAULT_BASE_URL,
    DEFAULT_CACHE_TTL, DEFAULT_RETRIES, DEFAULT_TIMEOUT, USER_AGENT,
};
use crate::crypto::{
    group_by_prefix, is_hash_in_set, prepare_credential, prepare_hash, validate_client_hmac,
};
use crate::errors::{DarkStrataError, Result};
use crate::types::{
    ApiResponse, CheckMetadata, CheckOptions, CheckResult, ClientOptions, Credential,
    CredentialInfo, HashedCredential, HmacSource, ResolvedConfig,
};
use chrono::Utc;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use url::Url;

/// Cache entry for API responses.
#[derive(Debug, Clone)]
struct CacheEntry {
    response: ApiResponse,
    time_window: i64,
    created_at: Instant,
}

/// DarkStrata credential check client.
///
/// This client provides methods to check if credentials have been exposed
/// in data breaches using k-anonymity privacy protection.
///
/// # Example
///
/// ```no_run
/// use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = DarkStrataCredentialCheck::new(
///         ClientOptions::new("your-api-key")
///     )?;
///
///     let result = client.check("user@example.com", "password123", None).await?;
///     if result.found {
///         println!("Credential has been compromised!");
///     }
///     Ok(())
/// }
/// ```
pub struct DarkStrataCredentialCheck {
    config: ResolvedConfig,
    http_client: Client,
    cache: RwLock<HashMap<String, CacheEntry>>,
}

impl DarkStrataCredentialCheck {
    /// Create a new DarkStrata credential check client.
    ///
    /// # Arguments
    ///
    /// * `options` - Client configuration options including API key.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(options: ClientOptions) -> Result<Self> {
        Self::validate_options(&options)?;

        let config = Self::resolve_config(options)?;
        let http_client = Self::build_http_client(&config)?;

        Ok(Self {
            config,
            http_client,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Check if a credential has been exposed in a data breach.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address.
    /// * `password` - The password.
    /// * `options` - Optional check parameters.
    ///
    /// # Returns
    ///
    /// A `CheckResult` indicating whether the credential was found.
    pub async fn check(
        &self,
        email: &str,
        password: &str,
        options: Option<CheckOptions>,
    ) -> Result<CheckResult> {
        let hashed = prepare_credential(email, password)?;
        self.check_hashed_credential(&hashed, options.as_ref())
            .await
    }

    /// Check if a pre-computed credential hash has been exposed.
    ///
    /// Use this method if you've already computed the SHA-256 hash of
    /// the credential (format: `{email}:{password}`).
    ///
    /// # Arguments
    ///
    /// * `hash` - The SHA-256 hash of the credential (64 hex characters).
    /// * `options` - Optional check parameters.
    ///
    /// # Returns
    ///
    /// A `CheckResult` indicating whether the hash was found.
    pub async fn check_hash(
        &self,
        hash: &str,
        options: Option<CheckOptions>,
    ) -> Result<CheckResult> {
        let hashed = prepare_hash(hash)?;
        self.check_hashed_credential(&hashed, options.as_ref())
            .await
    }

    /// Check multiple credentials in a batch.
    ///
    /// This method optimizes API calls by grouping credentials with the
    /// same hash prefix, making a single API call per unique prefix.
    ///
    /// # Arguments
    ///
    /// * `credentials` - List of credentials to check.
    /// * `options` - Optional check parameters (applied to all checks).
    ///
    /// # Returns
    ///
    /// A vector of `CheckResult`s in the same order as the input credentials.
    pub async fn check_batch(
        &self,
        credentials: &[Credential],
        options: Option<CheckOptions>,
    ) -> Result<Vec<CheckResult>> {
        if credentials.is_empty() {
            return Ok(Vec::new());
        }

        // Prepare all credentials
        let mut hashed_credentials = Vec::with_capacity(credentials.len());
        for cred in credentials {
            hashed_credentials.push(prepare_credential(&cred.email, &cred.password)?);
        }

        // Group by prefix for efficient API calls
        let groups = group_by_prefix(&hashed_credentials);

        // Fetch data for each unique prefix
        let mut prefix_responses: HashMap<String, ApiResponse> = HashMap::new();
        for prefix in groups.keys() {
            let response = self.fetch_prefix_data(prefix, options.as_ref()).await?;
            prefix_responses.insert(prefix.clone(), response);
        }

        // Check each credential against its prefix response
        let mut results = Vec::with_capacity(hashed_credentials.len());
        for hashed in &hashed_credentials {
            let response = prefix_responses
                .get(&hashed.prefix)
                .expect("Prefix response should exist");

            let found = is_hash_in_set(&hashed.hash, &response.hmac_key, &response.hashes)?;

            let result = self.build_check_result(hashed, response, found, false);
            results.push(result);
        }

        Ok(results)
    }

    /// Clear the response cache.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().expect("Cache lock poisoned");
        cache.clear();
    }

    /// Get the current cache size.
    pub fn cache_size(&self) -> usize {
        let cache = self.cache.read().expect("Cache lock poisoned");
        cache.len()
    }

    // Private implementation methods

    fn validate_options(options: &ClientOptions) -> Result<()> {
        if options.api_key.is_empty() {
            return Err(DarkStrataError::validation_field(
                "api_key",
                "API key is required",
            ));
        }

        if let Some(timeout) = options.timeout {
            if timeout.is_zero() {
                return Err(DarkStrataError::validation_field(
                    "timeout",
                    "Timeout must be greater than 0",
                ));
            }
        }

        if let Some(ttl) = options.cache_ttl {
            if ttl.is_zero() {
                return Err(DarkStrataError::validation_field(
                    "cache_ttl",
                    "Cache TTL must be greater than 0",
                ));
            }
        }

        Ok(())
    }

    fn resolve_config(options: ClientOptions) -> Result<ResolvedConfig> {
        let base_url = normalise_base_url(options.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL))?;

        Ok(ResolvedConfig {
            api_key: options.api_key,
            base_url,
            timeout: options.timeout.unwrap_or(DEFAULT_TIMEOUT),
            retries: options.retries.unwrap_or(DEFAULT_RETRIES),
            enable_caching: options.enable_caching.unwrap_or(true),
            cache_ttl: options.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL),
        })
    }

    fn build_http_client(config: &ResolvedConfig) -> Result<Client> {
        Client::builder()
            .timeout(config.timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| DarkStrataError::network(format!("Failed to create HTTP client: {}", e)))
    }

    async fn check_hashed_credential(
        &self,
        hashed: &HashedCredential,
        options: Option<&CheckOptions>,
    ) -> Result<CheckResult> {
        let response = self.fetch_prefix_data(&hashed.prefix, options).await?;
        let found = is_hash_in_set(&hashed.hash, &response.hmac_key, &response.hashes)?;
        let cached = false; // Track if result was from cache

        Ok(self.build_check_result(hashed, &response, found, cached))
    }

    async fn fetch_prefix_data(
        &self,
        prefix: &str,
        options: Option<&CheckOptions>,
    ) -> Result<ApiResponse> {
        // Validate options
        if let Some(opts) = options {
            if let Some(ref hmac) = opts.client_hmac {
                validate_client_hmac(hmac)?;
            }
        }

        // Check cache (only if caching enabled and no custom options)
        let can_cache = self.config.enable_caching
            && options.map_or(true, |o| o.client_hmac.is_none() && o.since.is_none());

        if can_cache {
            if let Some(cached) = self.get_cached_response(prefix) {
                return Ok(cached);
            }
        }

        // Make API request with retries
        let response = self.fetch_with_retry(prefix, options).await?;

        // Cache the response if applicable
        if can_cache {
            if let Some(time_window) = response.time_window {
                self.cache_response(prefix, &response, time_window);
            }
        }

        Ok(response)
    }

    async fn fetch_with_retry(
        &self,
        prefix: &str,
        options: Option<&CheckOptions>,
    ) -> Result<ApiResponse> {
        let mut last_error: Option<DarkStrataError> = None;
        let mut delay = retry::INITIAL_DELAY;

        for attempt in 0..=self.config.retries {
            match self.make_request(prefix, options).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if !e.is_retryable() || attempt == self.config.retries {
                        return Err(e);
                    }

                    // Handle rate limit retry-after
                    if let Some(retry_after) = e.retry_after() {
                        tokio::time::sleep(retry_after).await;
                    } else {
                        tokio::time::sleep(delay).await;
                        delay = (delay * retry::BACKOFF_MULTIPLIER).min(retry::MAX_DELAY);
                    }

                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| DarkStrataError::api("Request failed", None)))
    }

    async fn make_request(
        &self,
        prefix: &str,
        options: Option<&CheckOptions>,
    ) -> Result<ApiResponse> {
        let url = self.build_url(prefix, options)?;

        let response = self
            .http_client
            .get(url)
            .header(API_KEY_HEADER, &self.config.api_key)
            .send()
            .await?;

        let status = response.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DarkStrataError::authentication(
                "Invalid or missing API key",
            ));
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(DarkStrataError::rate_limit(retry_after));
        }

        if !status.is_success() {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(DarkStrataError::api(message, Some(status.as_u16())));
        }

        // Parse response headers
        let headers = response.headers();

        let response_prefix = headers
            .get(response_headers::PREFIX)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(prefix)
            .to_uppercase();

        let hmac_key = headers
            .get(response_headers::HMAC_KEY)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| DarkStrataError::api("Missing HMAC key header", Some(status.as_u16())))?
            .to_string();

        let hmac_source = headers
            .get(response_headers::HMAC_SOURCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(HmacSource::Server);

        let time_window = headers
            .get(response_headers::TIME_WINDOW)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        let filter_since = headers
            .get(response_headers::FILTER_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());

        // Parse response body
        let hashes: Vec<String> = response
            .json()
            .await
            .map_err(|e| DarkStrataError::api(format!("Failed to parse response: {}", e), None))?;

        Ok(ApiResponse {
            hashes,
            prefix: response_prefix,
            hmac_key,
            hmac_source,
            time_window,
            filter_since,
        })
    }

    fn build_url(&self, prefix: &str, options: Option<&CheckOptions>) -> Result<Url> {
        let mut url = Url::parse(&format!(
            "{}{}",
            self.config.base_url, CREDENTIAL_CHECK_ENDPOINT
        ))
        .map_err(|e| DarkStrataError::validation(format!("Invalid URL: {}", e)))?;

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("prefix", prefix);

            if let Some(opts) = options {
                if let Some(ref hmac) = opts.client_hmac {
                    query.append_pair("clientHmac", hmac);
                }
                if let Some(ref since) = opts.since {
                    query.append_pair("since", &since.to_epoch_day().to_string());
                }
            }
        }

        Ok(url)
    }

    fn get_cached_response(&self, prefix: &str) -> Option<ApiResponse> {
        let cache = self.cache.read().expect("Cache lock poisoned");
        let current_time_window = Utc::now().timestamp() / 3600;

        if let Some(entry) = cache.get(prefix) {
            // Check if still valid (same time window and not expired)
            let age = entry.created_at.elapsed();
            if entry.time_window == current_time_window && age < self.config.cache_ttl {
                return Some(entry.response.clone());
            }
        }

        None
    }

    fn cache_response(&self, prefix: &str, response: &ApiResponse, time_window: i64) {
        let mut cache = self.cache.write().expect("Cache lock poisoned");

        // Prune expired entries
        let current_time_window = Utc::now().timestamp() / 3600;
        cache.retain(|_, entry| {
            entry.time_window == current_time_window
                && entry.created_at.elapsed() < self.config.cache_ttl
        });

        // Cache key is just the prefix (time window is part of validation)
        cache.insert(
            prefix.to_string(),
            CacheEntry {
                response: response.clone(),
                time_window,
                created_at: Instant::now(),
            },
        );
    }

    fn build_check_result(
        &self,
        hashed: &HashedCredential,
        response: &ApiResponse,
        found: bool,
        cached: bool,
    ) -> CheckResult {
        let credential_info = if let Some(ref cred) = hashed.credential {
            CredentialInfo::new(&cred.email)
        } else {
            CredentialInfo::masked()
        };

        CheckResult {
            found,
            credential: credential_info,
            metadata: CheckMetadata {
                prefix: hashed.prefix.clone(),
                total_results: response.hashes.len(),
                hmac_source: response.hmac_source,
                time_window: response.time_window,
                filter_since: response.filter_since,
                cached_result: cached,
                checked_at: Utc::now(),
            },
        }
    }
}

/// Normalise a base URL to ensure it ends with a trailing slash.
fn normalise_base_url(url: &str) -> Result<String> {
    let mut normalized = url.to_string();
    if !normalized.ends_with('/') {
        normalized.push('/');
    }

    // Validate the URL
    Url::parse(&normalized)
        .map_err(|e| DarkStrataError::validation(format!("Invalid base URL: {}", e)))?;

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalise_base_url() {
        assert_eq!(
            normalise_base_url("https://api.example.com").unwrap(),
            "https://api.example.com/"
        );
        assert_eq!(
            normalise_base_url("https://api.example.com/").unwrap(),
            "https://api.example.com/"
        );
        assert_eq!(
            normalise_base_url("https://api.example.com/v1").unwrap(),
            "https://api.example.com/v1/"
        );
    }

    #[test]
    fn test_normalise_base_url_invalid() {
        assert!(normalise_base_url("not-a-url").is_err());
    }

    #[test]
    fn test_client_options_validation() {
        // Valid options
        assert!(DarkStrataCredentialCheck::new(ClientOptions::new("test-key")).is_ok());

        // Empty API key
        assert!(DarkStrataCredentialCheck::new(ClientOptions::new("")).is_err());

        // Zero timeout
        let options = ClientOptions::new("test-key").timeout(Duration::ZERO);
        assert!(DarkStrataCredentialCheck::new(options).is_err());

        // Zero cache TTL
        let options = ClientOptions::new("test-key").cache_ttl(Duration::ZERO);
        assert!(DarkStrataCredentialCheck::new(options).is_err());
    }

    #[test]
    fn test_resolve_config_defaults() {
        let options = ClientOptions::new("test-key");
        let config = DarkStrataCredentialCheck::resolve_config(options).unwrap();

        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.retries, DEFAULT_RETRIES);
        assert!(config.enable_caching);
        assert_eq!(config.cache_ttl, DEFAULT_CACHE_TTL);
    }

    #[test]
    fn test_resolve_config_custom() {
        let options = ClientOptions::new("test-key")
            .base_url("https://custom.api.com")
            .timeout(Duration::from_secs(60))
            .retries(5)
            .enable_caching(false)
            .cache_ttl(Duration::from_secs(1800));

        let config = DarkStrataCredentialCheck::resolve_config(options).unwrap();

        assert_eq!(config.base_url, "https://custom.api.com/");
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.retries, 5);
        assert!(!config.enable_caching);
        assert_eq!(config.cache_ttl, Duration::from_secs(1800));
    }

    #[test]
    fn test_build_url() {
        let client = DarkStrataCredentialCheck::new(ClientOptions::new("test-key")).unwrap();

        // Basic URL
        let url = client.build_url("5BAA6", None).unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.darkstrata.io/v1/credential-check/query?prefix=5BAA6"
        );

        // With client HMAC
        let options = CheckOptions::new()
            .client_hmac("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let url = client.build_url("5BAA6", Some(&options)).unwrap();
        assert!(url.as_str().contains("clientHmac="));

        // With since filter
        let options = CheckOptions::new().since_epoch_day(19724);
        let url = client.build_url("5BAA6", Some(&options)).unwrap();
        assert!(url.as_str().contains("since=19724"));
    }

    #[test]
    fn test_cache_operations() {
        let client = DarkStrataCredentialCheck::new(ClientOptions::new("test-key")).unwrap();

        assert_eq!(client.cache_size(), 0);

        // Manually add a cache entry for testing
        {
            let mut cache = client.cache.write().unwrap();
            cache.insert(
                "5BAA6".to_string(),
                CacheEntry {
                    response: ApiResponse {
                        hashes: vec!["test".to_string()],
                        prefix: "5BAA6".to_string(),
                        hmac_key: "key".to_string(),
                        hmac_source: HmacSource::Server,
                        time_window: Some(Utc::now().timestamp() / 3600),
                        filter_since: None,
                    },
                    time_window: Utc::now().timestamp() / 3600,
                    created_at: Instant::now(),
                },
            );
        }

        assert_eq!(client.cache_size(), 1);

        client.clear_cache();
        assert_eq!(client.cache_size(), 0);
    }
}
