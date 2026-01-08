package main

import (
	"context"
	"fmt"
	"log"
	"os"

	credentialcheck "github.com/darkstrata/darkstrata-sdks/go"
)

func main() {
	// Create client
	client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
		APIKey: os.Getenv("DARKSTRATA_API_KEY"),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Define multiple credentials to check
	credentials := []credentialcheck.Credential{
		{Email: "alice@example.com", Password: "alice123"},
		{Email: "bob@example.com", Password: "bob456"},
		{Email: "charlie@example.com", Password: "charlie789"},
		{Email: "diana@example.com", Password: "diana000"},
	}

	// Check all credentials in batch
	// The SDK automatically groups credentials by hash prefix
	// to minimize API calls
	results, err := client.CheckBatch(ctx, credentials, nil)
	if err != nil {
		log.Fatalf("Batch check failed: %v", err)
	}

	// Process results
	compromised := 0
	safe := 0

	for i, result := range results {
		if result.Found {
			compromised++
			fmt.Printf("COMPROMISED: %s\n", credentials[i].Email)
		} else {
			safe++
			fmt.Printf("Safe: %s\n", credentials[i].Email)
		}
	}

	fmt.Printf("\nSummary: %d compromised, %d safe out of %d total\n",
		compromised, safe, len(credentials))

	// Check cache statistics
	fmt.Printf("Cache size: %d entries\n", client.GetCacheSize())

	// Clear cache if needed
	client.ClearCache()
	fmt.Printf("Cache cleared. New size: %d entries\n", client.GetCacheSize())
}
