package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	credentialcheck "github.com/darkstrata/darkstrata-sdks/go"
)

func main() {
	// Create client with API key
	client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
		APIKey: os.Getenv("DARKSTRATA_API_KEY"),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Check a single credential
	result, err := client.Check(ctx, "user@example.com", "password123", nil)
	if err != nil {
		log.Fatalf("Check failed: %v", err)
	}

	if result.Found {
		fmt.Println("WARNING: This credential was found in a data breach!")
	} else {
		fmt.Println("OK: This credential was not found in known breaches.")
	}

	fmt.Printf("Checked at: %v\n", result.Metadata.CheckedAt)
	fmt.Printf("Total results for prefix: %d\n", result.Metadata.TotalResults)
	fmt.Printf("HMAC source: %s\n", result.Metadata.HMACSource)

	// Check with options
	since := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	resultWithOpts, err := client.Check(ctx, "user@example.com", "password123", &credentialcheck.CheckOptions{
		Since: &since,
	})
	if err != nil {
		log.Fatalf("Check with options failed: %v", err)
	}

	fmt.Printf("\nWith 'since' filter - Found: %v\n", resultWithOpts.Found)

	// Check a pre-computed hash
	hash := credentialcheck.HashCredential("user@example.com", "password123")
	hashResult, err := client.CheckHash(ctx, hash, nil)
	if err != nil {
		log.Fatalf("Hash check failed: %v", err)
	}

	fmt.Printf("\nHash check - Found: %v\n", hashResult.Found)
}
