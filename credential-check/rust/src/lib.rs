//! DarkStrata Credential Check SDK for Rust
//!
//! This SDK provides a secure way to check if credentials have been exposed
//! in data breaches using k-anonymity privacy protection.
//!
//! # Overview
//!
//! The SDK sends only a 5-character hash prefix to the API (k-anonymity),
//! ensuring that your actual credentials are never exposed. The API returns
//! all hashes matching the prefix, and the client checks for a match locally
//! using timing-safe comparison.
//!
//! # Quick Start
//!
//! ```no_run
//! use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a client with your API key
//!     let client = DarkStrataCredentialCheck::new(
//!         ClientOptions::new("your-api-key")
//!     )?;
//!
//!     // Check a single credential
//!     let result = client.check("user@example.com", "password123", None).await?;
//!     if result.found {
//!         println!("This credential has been compromised!");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Batch Checking
//!
//! ```no_run
//! use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions, Credential};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = DarkStrataCredentialCheck::new(
//!         ClientOptions::new("your-api-key")
//!     )?;
//!
//!     let credentials = vec![
//!         Credential::new("alice@example.com", "pass1"),
//!         Credential::new("bob@example.com", "pass2"),
//!     ];
//!
//!     let results = client.check_batch(&credentials, None).await?;
//!     for (cred, result) in credentials.iter().zip(results.iter()) {
//!         println!("{}: {}", cred.email, if result.found { "compromised" } else { "safe" });
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Configuration Options
//!
//! ```no_run
//! use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions};
//! use std::time::Duration;
//!
//! let client = DarkStrataCredentialCheck::new(
//!     ClientOptions::new("your-api-key")
//!         .base_url("https://custom.api.com/v1/")
//!         .timeout(Duration::from_secs(60))
//!         .retries(5)
//!         .enable_caching(true)
//!         .cache_ttl(Duration::from_secs(1800))
//! )?;
//! # Ok::<(), darkstrata_credential_check::DarkStrataError>(())
//! ```
//!
//! # Check Options
//!
//! ```no_run
//! use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions, CheckOptions};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = DarkStrataCredentialCheck::new(ClientOptions::new("your-api-key"))?;
//!
//! // Filter by date
//! let result = client.check(
//!     "user@example.com",
//!     "password",
//!     Some(CheckOptions::new().since_epoch_day(19724))
//! ).await?;
//!
//! // Use custom HMAC key
//! let result = client.check(
//!     "user@example.com",
//!     "password",
//!     Some(CheckOptions::new().client_hmac(
//!         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
//!     ))
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! ```no_run
//! use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions, DarkStrataError};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = DarkStrataCredentialCheck::new(ClientOptions::new("your-api-key"))?;
//!
//! match client.check("user@example.com", "password", None).await {
//!     Ok(result) => {
//!         if result.found {
//!             println!("Credential compromised!");
//!         }
//!     }
//!     Err(DarkStrataError::RateLimit { retry_after }) => {
//!         if let Some(duration) = retry_after {
//!             println!("Rate limited. Retry after {:?}", duration);
//!         }
//!     }
//!     Err(DarkStrataError::Authentication { .. }) => {
//!         println!("Invalid API key");
//!     }
//!     Err(e) if e.is_retryable() => {
//!         println!("Transient error, can retry: {}", e);
//!     }
//!     Err(e) => {
//!         println!("Error: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

mod client;
mod constants;
mod crypto;
mod errors;
mod types;

// Re-export main client
pub use client::DarkStrataCredentialCheck;

// Re-export types
pub use types::{
    CheckMetadata, CheckOptions, CheckResult, ClientOptions, Credential, CredentialInfo,
    HmacSource, SinceFilter,
};

// Re-export errors
pub use errors::{is_retryable_status, DarkStrataError, Result};

/// Cryptographic utilities for advanced usage.
///
/// These functions are exposed for users who want to pre-compute hashes
/// or implement custom processing logic.
pub mod crypto_utils {
    pub use crate::crypto::{
        extract_prefix, hash_credential, hmac_sha256, is_hash_in_set, is_valid_hash,
        is_valid_prefix, sha256, validate_client_hmac,
    };
}

/// Configuration constants.
///
/// These are exposed for users who want to reference default values
/// or implement custom logic that aligns with the SDK's behavior.
pub mod config {
    pub use crate::constants::{
        response_headers, retry, API_KEY_HEADER, CREDENTIAL_CHECK_ENDPOINT, DEFAULT_BASE_URL,
        DEFAULT_CACHE_TTL, DEFAULT_RETRIES, DEFAULT_TIMEOUT, MIN_CLIENT_HMAC_LENGTH, PREFIX_LENGTH,
        SHA256_HEX_LENGTH, TIME_WINDOW_SECONDS, USER_AGENT,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_exports() {
        // Verify main types are exported
        let _ = ClientOptions::new("test");
        let _ = CheckOptions::new();
        let _ = Credential::new("test@example.com", "password");

        // Verify error types
        let err = DarkStrataError::validation("test");
        assert!(!err.is_retryable());

        // Verify crypto utils
        let hash = crypto_utils::sha256("test");
        assert_eq!(hash.len(), 64);

        // Verify constants
        assert_eq!(config::PREFIX_LENGTH, 5);
    }
}
