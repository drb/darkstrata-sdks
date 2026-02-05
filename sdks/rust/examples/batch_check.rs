//! Batch check example for the DarkStrata Credential Check SDK.
//!
//! This example demonstrates:
//! - Checking multiple credentials efficiently in a batch
//! - Understanding the optimization benefits of batch checking
//! - Processing batch results
//!
//! Run with:
//! ```bash
//! DARKSTRATA_API_KEY=your-key cargo run --example batch_check
//! ```

use darkstrata_credential_check::{ClientOptions, Credential, DarkStrataCredentialCheck};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get API key from environment variable
    let api_key = env::var("DARKSTRATA_API_KEY")
        .expect("DARKSTRATA_API_KEY environment variable must be set");

    // Create a client with default configuration
    let client = DarkStrataCredentialCheck::new(ClientOptions::new(api_key))?;

    println!("DarkStrata Credential Check - Batch Check Example\n");

    // Create a list of credentials to check
    let credentials = vec![
        Credential::new("alice@example.com", "password123"),
        Credential::new("bob@example.com", "securepass"),
        Credential::new("carol@example.com", "mypassword"),
        Credential::new("dave@example.com", "letmein"),
        Credential::new("eve@example.com", "qwerty123"),
    ];

    println!("Checking {} credentials in batch...\n", credentials.len());

    // Perform batch check
    let start = std::time::Instant::now();
    let results = client.check_batch(&credentials, None).await?;
    let duration = start.elapsed();

    // Display results
    println!("Results:");
    println!("{:-<60}", "");

    let mut compromised_count = 0;
    let mut unique_prefixes = std::collections::HashSet::new();

    for (credential, result) in credentials.iter().zip(results.iter()) {
        let status = if result.found {
            compromised_count += 1;
            "COMPROMISED"
        } else {
            "SAFE"
        };

        unique_prefixes.insert(result.metadata.prefix.clone());

        println!(
            "  {} - {} (prefix: {})",
            credential.email, status, result.metadata.prefix
        );
    }

    println!("{:-<60}", "");
    println!();

    // Summary statistics
    println!("Summary:");
    println!("  Total credentials checked: {}", credentials.len());
    println!("  Compromised: {}", compromised_count);
    println!("  Safe: {}", credentials.len() - compromised_count);
    println!(
        "  Unique prefixes (API calls made): {}",
        unique_prefixes.len()
    );
    println!("  Time taken: {:?}", duration);
    println!();

    // Explain the optimization
    println!("Optimization note:");
    println!(
        "  Without batching, {} API calls would be needed (one per credential).",
        credentials.len()
    );
    println!(
        "  With batching, only {} API calls were made (one per unique prefix).",
        unique_prefixes.len()
    );
    println!(
        "  This reduced API calls by {:.1}%!",
        (1.0 - (unique_prefixes.len() as f64 / credentials.len() as f64)) * 100.0
    );

    println!("\nBatch check example completed successfully!");

    Ok(())
}
