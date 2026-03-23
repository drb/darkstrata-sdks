//! Error handling example for the DarkStrata Credential Check SDK.
//!
//! This example demonstrates:
//! - Different error types and how to handle them
//! - Using the is_retryable() method
//! - Accessing error details like status codes and retry-after durations
//!
//! Run with:
//! ```bash
//! DARKSTRATA_API_KEY=your-key cargo run --example error_handling
//! ```

use darkstrata_credential_check::{ClientOptions, DarkStrataCredentialCheck, DarkStrataError};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DarkStrata Credential Check - Error Handling Example\n");

    // Example 1: Invalid API key
    println!("1. Testing with invalid API key...");
    match DarkStrataCredentialCheck::new(ClientOptions::new("invalid-key")) {
        Ok(client) => {
            // Client creation succeeded, but API call will fail
            match client.check("test@example.com", "password", None).await {
                Ok(_) => println!("   Unexpected success!"),
                Err(e) => {
                    println!("   Error: {}", e);
                    println!("   Retryable: {}", e.is_retryable());
                    if let Some(code) = e.status_code() {
                        println!("   Status code: {}", code);
                    }
                }
            }
        }
        Err(e) => {
            println!("   Failed to create client: {}", e);
        }
    }
    println!();

    // Example 2: Validation errors
    println!("2. Testing validation errors...");

    // Empty API key
    match DarkStrataCredentialCheck::new(ClientOptions::new("")) {
        Ok(_) => println!("   Unexpected success with empty API key!"),
        Err(DarkStrataError::Validation { message, field }) => {
            println!("   Validation error: {}", message);
            if let Some(f) = field {
                println!("   Field: {}", f);
            }
        }
        Err(e) => println!("   Other error: {}", e),
    }

    // Zero timeout
    let options = ClientOptions::new("test-key").timeout(Duration::ZERO);
    match DarkStrataCredentialCheck::new(options) {
        Ok(_) => println!("   Unexpected success with zero timeout!"),
        Err(DarkStrataError::Validation { message, .. }) => {
            println!("   Validation error: {}", message);
        }
        Err(e) => println!("   Other error: {}", e),
    }
    println!();

    // Example 3: Comprehensive error handling pattern
    println!("3. Comprehensive error handling pattern:");
    println!();

    // Get API key for real API testing
    let api_key = env::var("DARKSTRATA_API_KEY").ok();

    if let Some(key) = api_key {
        let client = DarkStrataCredentialCheck::new(ClientOptions::new(key))?;

        match client.check("test@example.com", "password", None).await {
            Ok(result) => {
                println!("   Success!");
                println!("   Found: {}", result.found);
            }
            Err(e) => handle_error(&e),
        }
    } else {
        println!("   Skipping API test (DARKSTRATA_API_KEY not set)");
        println!("   Demonstrating error handling patterns...");
        println!();

        // Demonstrate error creation and handling
        let errors: Vec<DarkStrataError> = vec![
            DarkStrataError::authentication("Invalid API key"),
            DarkStrataError::validation("Email is required"),
            DarkStrataError::api("Server error", Some(500)),
            DarkStrataError::timeout(Duration::from_secs(30)),
            DarkStrataError::network("Connection refused"),
            DarkStrataError::rate_limit(Some(Duration::from_secs(60))),
        ];

        for error in errors {
            handle_error(&error);
            println!();
        }
    }

    println!("\nError handling example completed!");

    Ok(())
}

fn handle_error(error: &DarkStrataError) {
    println!("   Error type: {:?}", std::mem::discriminant(error));
    println!("   Message: {}", error);
    println!("   Retryable: {}", error.is_retryable());

    if let Some(code) = error.status_code() {
        println!("   HTTP Status: {}", code);
    }

    match error {
        DarkStrataError::Authentication { .. } => {
            println!("   Action: Check your API key and try again");
        }
        DarkStrataError::Validation { field, .. } => {
            if let Some(f) = field {
                println!("   Action: Fix the '{}' field and try again", f);
            } else {
                println!("   Action: Check your input and try again");
            }
        }
        DarkStrataError::Api { retryable, .. } => {
            if *retryable {
                println!("   Action: Wait and retry the request");
            } else {
                println!("   Action: Check the request and try again");
            }
        }
        DarkStrataError::Timeout { duration } => {
            println!(
                "   Action: Request timed out after {:?}, consider increasing timeout",
                duration
            );
        }
        DarkStrataError::Network { .. } => {
            println!("   Action: Check network connectivity and retry");
        }
        DarkStrataError::RateLimit { retry_after } => {
            if let Some(duration) = retry_after {
                println!("   Action: Wait {:?} before retrying", duration);
            } else {
                println!("   Action: Wait before retrying (no duration specified)");
            }
        }
    }
}
