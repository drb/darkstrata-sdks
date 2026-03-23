//! Integration tests for the DarkStrata Credential Check SDK.

use chrono::Utc;
use darkstrata_credential_check::{
    config, crypto_utils, CheckOptions, ClientOptions, Credential, DarkStrataCredentialCheck,
    DarkStrataError, HmacSource,
};
use std::time::Duration;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper to create a mock server response.
fn mock_response(hashes: Vec<&str>, hmac_key: &str) -> ResponseTemplate {
    let body: Vec<String> = hashes.into_iter().map(String::from).collect();
    // Use the current hour as the time window to match what the client expects
    let current_time_window = Utc::now().timestamp() / 3600;

    ResponseTemplate::new(200)
        .set_body_json(body)
        .insert_header("x-prefix", "5BAA6")
        .insert_header("x-hmac-key", hmac_key)
        .insert_header("x-hmac-source", "server")
        .insert_header("x-time-window", current_time_window.to_string())
        .insert_header("x-total-results", "2")
}

#[tokio::test]
async fn test_check_credential_found() {
    let mock_server = MockServer::start().await;

    // Pre-compute the expected HMAC
    let email = "test@example.com";
    let password = "password123";
    let credential_hash = crypto_utils::hash_credential(email, password);
    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let expected_hmac = crypto_utils::hmac_sha256(&credential_hash, hmac_key).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .and(query_param("prefix", &credential_hash[..5]))
        .and(header("X-Api-Key", "test-api-key"))
        .respond_with(mock_response(
            vec![
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &expected_hmac,
            ],
            hmac_key,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key").base_url(format!("{}/v1/", mock_server.uri())),
    )
    .unwrap();

    let result = client.check(email, password, None).await.unwrap();

    assert!(result.found);
    assert_eq!(result.credential.email, email);
    assert!(result.credential.masked);
    assert_eq!(result.metadata.hmac_source, HmacSource::Server);
    assert_eq!(result.metadata.total_results, 2);
}

#[tokio::test]
async fn test_check_credential_not_found() {
    let mock_server = MockServer::start().await;

    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(mock_response(
            vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            hmac_key,
        ))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key").base_url(format!("{}/v1/", mock_server.uri())),
    )
    .unwrap();

    let result = client
        .check("notfound@example.com", "safepassword", None)
        .await
        .unwrap();

    assert!(!result.found);
}

#[tokio::test]
async fn test_check_hash() {
    let mock_server = MockServer::start().await;

    let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let expected_hmac = crypto_utils::hmac_sha256(hash, hmac_key).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .and(query_param("prefix", "5BAA6"))
        .respond_with(mock_response(vec![&expected_hmac], hmac_key))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key").base_url(format!("{}/v1/", mock_server.uri())),
    )
    .unwrap();

    let result = client.check_hash(hash, None).await.unwrap();

    assert!(result.found);
    assert_eq!(result.credential.email, "[hash]");
}

#[tokio::test]
async fn test_batch_check() {
    let mock_server = MockServer::start().await;

    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Set up mock for any prefix
    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(mock_response(
            vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            hmac_key,
        ))
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key").base_url(format!("{}/v1/", mock_server.uri())),
    )
    .unwrap();

    let credentials = vec![
        Credential::new("alice@example.com", "pass1"),
        Credential::new("bob@example.com", "pass2"),
        Credential::new("carol@example.com", "pass3"),
    ];

    let results = client.check_batch(&credentials, None).await.unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].credential.email, "alice@example.com");
    assert_eq!(results[1].credential.email, "bob@example.com");
    assert_eq!(results[2].credential.email, "carol@example.com");
}

#[tokio::test]
async fn test_check_with_since_filter() {
    let mock_server = MockServer::start().await;

    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .and(query_param("since", "19724"))
        .respond_with(mock_response(vec![], hmac_key).insert_header("x-filter-since", "19724"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key")
            .base_url(format!("{}/v1/", mock_server.uri()))
            .enable_caching(false),
    )
    .unwrap();

    let options = CheckOptions::new().since_epoch_day(19724);
    let result = client
        .check("test@example.com", "password", Some(options))
        .await
        .unwrap();

    assert!(!result.found);
    assert_eq!(result.metadata.filter_since, Some(19724));
}

#[tokio::test]
async fn test_check_with_client_hmac() {
    let mock_server = MockServer::start().await;

    let client_hmac = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .and(query_param("clientHmac", client_hmac))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(Vec::<String>::new())
                .insert_header("x-prefix", "5BAA6")
                .insert_header("x-hmac-key", client_hmac)
                .insert_header("x-hmac-source", "client")
                .insert_header("x-total-results", "0"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key")
            .base_url(format!("{}/v1/", mock_server.uri()))
            .enable_caching(false),
    )
    .unwrap();

    let options = CheckOptions::new().client_hmac(client_hmac);
    let result = client
        .check("test@example.com", "password", Some(options))
        .await
        .unwrap();

    assert_eq!(result.metadata.hmac_source, HmacSource::Client);
}

#[tokio::test]
async fn test_authentication_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("invalid-key").base_url(format!("{}/v1/", mock_server.uri())),
    )
    .unwrap();

    let result = client.check("test@example.com", "password", None).await;

    assert!(matches!(
        result,
        Err(DarkStrataError::Authentication { .. })
    ));
}

#[tokio::test]
async fn test_rate_limit_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string("Too Many Requests")
                .insert_header("retry-after", "60"),
        )
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key")
            .base_url(format!("{}/v1/", mock_server.uri()))
            .retries(0), // Disable retries for this test
    )
    .unwrap();

    let result = client.check("test@example.com", "password", None).await;

    match result {
        Err(DarkStrataError::RateLimit { retry_after }) => {
            assert_eq!(retry_after, Some(Duration::from_secs(60)));
        }
        _ => panic!("Expected RateLimit error"),
    }
}

#[tokio::test]
async fn test_validation_errors() {
    let client = DarkStrataCredentialCheck::new(ClientOptions::new("test-api-key")).unwrap();

    // Empty email
    let result = client.check("", "password", None).await;
    assert!(matches!(result, Err(DarkStrataError::Validation { .. })));

    // Empty password
    let result = client.check("test@example.com", "", None).await;
    assert!(matches!(result, Err(DarkStrataError::Validation { .. })));

    // Invalid hash
    let result = client.check_hash("not-a-valid-hash", None).await;
    assert!(matches!(result, Err(DarkStrataError::Validation { .. })));

    // Invalid client HMAC (too short)
    let options = CheckOptions::new().client_hmac("tooshort");
    let result = client
        .check("test@example.com", "password", Some(options))
        .await;
    assert!(matches!(result, Err(DarkStrataError::Validation { .. })));
}

#[tokio::test]
async fn test_caching() {
    let mock_server = MockServer::start().await;

    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(mock_response(vec![], hmac_key))
        .expect(1) // Should only be called once due to caching
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key")
            .base_url(format!("{}/v1/", mock_server.uri()))
            .enable_caching(true),
    )
    .unwrap();

    // First call - should hit the server
    let _ = client
        .check("test@example.com", "password", None)
        .await
        .unwrap();

    // Second call with same prefix - should use cache
    let _ = client
        .check("test@example.com", "password", None)
        .await
        .unwrap();

    // Verify mock was only called once
    // (wiremock will panic if expect(1) is violated)
}

#[tokio::test]
async fn test_cache_disabled_with_options() {
    let mock_server = MockServer::start().await;

    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(mock_response(vec![], hmac_key))
        .expect(2) // Should be called twice when options are provided
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key")
            .base_url(format!("{}/v1/", mock_server.uri()))
            .enable_caching(true),
    )
    .unwrap();

    let options = CheckOptions::new().since_epoch_day(19724);

    // Both calls should hit the server (caching disabled with options)
    let _ = client
        .check("test@example.com", "password", Some(options.clone()))
        .await
        .unwrap();
    let _ = client
        .check("test@example.com", "password", Some(options))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_clear_cache() {
    let mock_server = MockServer::start().await;

    let hmac_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    Mock::given(method("GET"))
        .and(path("/v1/credential-check/query"))
        .respond_with(mock_response(vec![], hmac_key))
        .expect(2)
        .mount(&mock_server)
        .await;

    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("test-api-key")
            .base_url(format!("{}/v1/", mock_server.uri()))
            .enable_caching(true),
    )
    .unwrap();

    // First call
    let _ = client
        .check("test@example.com", "password", None)
        .await
        .unwrap();
    assert_eq!(client.cache_size(), 1);

    // Clear cache
    client.clear_cache();
    assert_eq!(client.cache_size(), 0);

    // Second call should hit server again
    let _ = client
        .check("test@example.com", "password", None)
        .await
        .unwrap();
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
fn test_crypto_utilities() {
    // SHA-256
    let hash = crypto_utils::sha256("test");
    assert_eq!(hash.len(), 64);
    assert!(crypto_utils::is_valid_hash(&hash, None));

    // Hash credential
    let hash = crypto_utils::hash_credential("test@example.com", "password");
    assert_eq!(hash.len(), 64);

    // Extract prefix
    let prefix = crypto_utils::extract_prefix(&hash);
    assert_eq!(prefix.len(), config::PREFIX_LENGTH);
    assert!(crypto_utils::is_valid_prefix(&prefix));

    // HMAC
    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let hmac = crypto_utils::hmac_sha256("message", key).unwrap();
    assert_eq!(hmac.len(), 64);

    // Validate client HMAC
    assert!(crypto_utils::validate_client_hmac(key).is_ok());
    assert!(crypto_utils::validate_client_hmac("tooshort").is_err());
}

#[test]
fn test_since_filter_conversion() {
    use darkstrata_credential_check::SinceFilter;

    // Epoch day
    let filter = SinceFilter::EpochDay(19723);
    assert_eq!(filter.to_epoch_day(), 19723);

    // Timestamp: 1704067200 = 2024-01-01 00:00:00 UTC
    // 1704067200 / 86400 = 19723 days since epoch
    let filter = SinceFilter::Timestamp(1704067200);
    assert_eq!(filter.to_epoch_day(), 19723);
}
