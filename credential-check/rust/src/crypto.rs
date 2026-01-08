//! Cryptographic utilities for the DarkStrata Credential Check SDK.

use crate::constants::{MIN_CLIENT_HMAC_LENGTH, PREFIX_LENGTH, SHA256_HEX_LENGTH};
use crate::errors::{DarkStrataError, Result};
use crate::types::HashedCredential;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Compute the SHA-256 hash of a string, returning uppercase hex.
pub fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode_upper(result)
}

/// Compute the HMAC-SHA256 of a message with the given key.
///
/// Both key and result are hex strings.
pub fn hmac_sha256(message: &str, key: &str) -> Result<String> {
    let key_bytes = hex::decode(key).map_err(|e| {
        DarkStrataError::validation(format!("Invalid HMAC key (not valid hex): {}", e))
    })?;

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| DarkStrataError::validation(format!("Invalid HMAC key: {}", e)))?;

    mac.update(message.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode_upper(result.into_bytes()))
}

/// Hash a credential (email:password) using SHA-256.
pub fn hash_credential(email: &str, password: &str) -> String {
    let credential = format!("{}:{}", email, password);
    sha256(&credential)
}

/// Extract the k-anonymity prefix from a hash.
pub fn extract_prefix(hash: &str) -> String {
    hash.chars()
        .take(PREFIX_LENGTH)
        .collect::<String>()
        .to_uppercase()
}

/// Check if a hash exists in a set of HMAC'd hashes using timing-safe comparison.
///
/// This computes `HMAC(hash, hmac_key)` and checks if the result exists in `hmac_hashes`.
/// Uses constant-time comparison to prevent timing attacks.
pub fn is_hash_in_set(hash: &str, hmac_key: &str, hmac_hashes: &[String]) -> Result<bool> {
    let target_hmac = hmac_sha256(hash, hmac_key)?;
    let target_bytes = hex::decode(&target_hmac)
        .map_err(|e| DarkStrataError::validation(format!("Failed to decode target HMAC: {}", e)))?;

    for hmac_hash in hmac_hashes {
        let candidate_bytes = match hex::decode(hmac_hash) {
            Ok(bytes) => bytes,
            Err(_) => continue, // Skip invalid hashes
        };

        if candidate_bytes.len() != target_bytes.len() {
            continue;
        }

        // Constant-time comparison
        if target_bytes.ct_eq(&candidate_bytes).into() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Validate that a string is a valid hex-encoded hash.
pub fn is_valid_hash(hash: &str, expected_length: Option<usize>) -> bool {
    let expected_len = expected_length.unwrap_or(SHA256_HEX_LENGTH);

    if hash.len() != expected_len {
        return false;
    }

    hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate that a string is a valid k-anonymity prefix.
pub fn is_valid_prefix(prefix: &str) -> bool {
    prefix.len() == PREFIX_LENGTH && prefix.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a client HMAC key.
pub fn validate_client_hmac(hmac: &str) -> Result<()> {
    if hmac.len() < MIN_CLIENT_HMAC_LENGTH {
        return Err(DarkStrataError::validation(format!(
            "Client HMAC key must be at least {} hex characters (256 bits)",
            MIN_CLIENT_HMAC_LENGTH
        )));
    }

    if !hmac.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DarkStrataError::validation(
            "Client HMAC key must be a valid hex string",
        ));
    }

    Ok(())
}

/// Group credentials by their hash prefix for batch optimization.
pub fn group_by_prefix(
    credentials: &[HashedCredential],
) -> HashMap<String, Vec<&HashedCredential>> {
    let mut groups: HashMap<String, Vec<&HashedCredential>> = HashMap::new();

    for cred in credentials {
        groups.entry(cred.prefix.clone()).or_default().push(cred);
    }

    groups
}

/// Prepare a credential for checking by computing its hash and prefix.
pub fn prepare_credential(email: &str, password: &str) -> Result<HashedCredential> {
    if email.is_empty() {
        return Err(DarkStrataError::validation_field(
            "email",
            "Email is required",
        ));
    }
    if password.is_empty() {
        return Err(DarkStrataError::validation_field(
            "password",
            "Password is required",
        ));
    }

    let hash = hash_credential(email, password);
    let prefix = extract_prefix(&hash);

    Ok(HashedCredential {
        credential: Some(crate::types::Credential {
            email: email.to_string(),
            password: password.to_string(),
        }),
        hash,
        prefix,
    })
}

/// Prepare a pre-computed hash for checking.
pub fn prepare_hash(hash: &str) -> Result<HashedCredential> {
    let hash_upper = hash.to_uppercase();

    if !is_valid_hash(&hash_upper, None) {
        return Err(DarkStrataError::validation(format!(
            "Invalid hash: must be {} hex characters",
            SHA256_HEX_LENGTH
        )));
    }

    let prefix = extract_prefix(&hash_upper);

    Ok(HashedCredential {
        credential: None,
        hash: hash_upper,
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        // Test vector: SHA-256 of "test@example.com:password123"
        let hash = sha256("test@example.com:password123");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // Hash should be uppercase
        assert!(hash.chars().all(|c| !c.is_ascii_lowercase()));
    }

    #[test]
    fn test_hash_credential() {
        let hash1 = hash_credential("test@example.com", "password123");
        let hash2 = hash_credential("test@example.com", "password123");
        assert_eq!(hash1, hash2);

        let hash3 = hash_credential("test@example.com", "different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_extract_prefix() {
        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let prefix = extract_prefix(hash);
        assert_eq!(prefix, "5BAA6");
        assert_eq!(prefix.len(), PREFIX_LENGTH);
    }

    #[test]
    fn test_extract_prefix_lowercase() {
        let hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
        let prefix = extract_prefix(hash);
        assert_eq!(prefix, "5BAA6");
    }

    #[test]
    fn test_hmac_sha256() {
        // Test with a known key
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let message = "test message";
        let result = hmac_sha256(message, key).unwrap();
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_sha256_invalid_key() {
        let result = hmac_sha256("message", "not-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_hash() {
        let valid_hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        assert!(is_valid_hash(valid_hash, None));

        // Too short
        assert!(!is_valid_hash("5BAA61E4", None));

        // Invalid characters
        assert!(!is_valid_hash(
            "ZZZZ61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000",
            None
        ));

        // Custom length
        assert!(is_valid_hash("5BAA6", Some(5)));
    }

    #[test]
    fn test_is_valid_prefix() {
        assert!(is_valid_prefix("5BAA6"));
        assert!(is_valid_prefix("abcde"));
        assert!(is_valid_prefix("12345"));

        // Wrong length
        assert!(!is_valid_prefix("5BAA"));
        assert!(!is_valid_prefix("5BAA61"));

        // Invalid characters
        assert!(!is_valid_prefix("5BAA!"));
    }

    #[test]
    fn test_validate_client_hmac() {
        // Valid HMAC (64 hex chars)
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_client_hmac(valid).is_ok());

        // Too short
        let short = "0123456789abcdef";
        assert!(validate_client_hmac(short).is_err());

        // Invalid hex
        let invalid = "GGGG456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_client_hmac(invalid).is_err());
    }

    #[test]
    fn test_is_hash_in_set() {
        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Compute what the HMAC should be
        let expected_hmac = hmac_sha256(hash, key).unwrap();

        // Hash should be found when its HMAC is in the set
        let hashes = vec![
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            expected_hmac.clone(),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        ];
        assert!(is_hash_in_set(hash, key, &hashes).unwrap());

        // Hash should not be found when its HMAC is not in the set
        let other_hashes = vec![
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        ];
        assert!(!is_hash_in_set(hash, key, &other_hashes).unwrap());
    }

    #[test]
    fn test_prepare_credential() {
        let result = prepare_credential("test@example.com", "password123").unwrap();
        assert_eq!(result.hash.len(), 64);
        assert_eq!(result.prefix.len(), 5);
        assert!(result.credential.is_some());
    }

    #[test]
    fn test_prepare_credential_empty_email() {
        let result = prepare_credential("", "password123");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_credential_empty_password() {
        let result = prepare_credential("test@example.com", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_hash() {
        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        let result = prepare_hash(hash).unwrap();
        assert_eq!(result.hash, hash);
        assert_eq!(result.prefix, "5BAA6");
        assert!(result.credential.is_none());
    }

    #[test]
    fn test_prepare_hash_invalid() {
        let result = prepare_hash("not-a-valid-hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_group_by_prefix() {
        let creds = vec![
            HashedCredential {
                credential: None,
                hash: "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000"
                    .to_string(),
                prefix: "5BAA6".to_string(),
            },
            HashedCredential {
                credential: None,
                hash: "5BAA71E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000"
                    .to_string(),
                prefix: "5BAA7".to_string(),
            },
            HashedCredential {
                credential: None,
                hash: "5BAA62E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000"
                    .to_string(),
                prefix: "5BAA6".to_string(),
            },
        ];

        let groups = group_by_prefix(&creds);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get("5BAA6").unwrap().len(), 2);
        assert_eq!(groups.get("5BAA7").unwrap().len(), 1);
    }
}
