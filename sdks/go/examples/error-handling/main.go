package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	credentialcheck "github.com/darkstrata/darkstrata-sdks/sdks/go"
)

func main() {
	// Example 1: Validation errors (caught before creating client)
	_, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
		APIKey: "", // Empty API key
	})
	if err != nil {
		if valErr, ok := err.(*credentialcheck.ValidationError); ok {
			fmt.Printf("Validation error on field '%s': %s\n", valErr.Field, valErr.Message)
		}
	}

	// Create a valid client
	client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
		APIKey:  os.Getenv("DARKSTRATA_API_KEY"),
		Timeout: 5 * time.Second, // Short timeout for demonstration
		Retries: 2,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Example 2: Handle all error types
	result, err := client.Check(ctx, "user@example.com", "password123", nil)
	if err != nil {
		handleError(err)
		return
	}

	fmt.Printf("Check completed. Found: %v\n", result.Found)

	// Example 3: Context cancellation
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = client.Check(ctx, "user@example.com", "password123", nil)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Println("Request timed out due to context deadline")
		}
		handleError(err)
	}
}

func handleError(err error) {
	// Check if it's a DarkStrata error
	if !credentialcheck.IsDarkStrataError(err) {
		fmt.Printf("Unknown error: %v\n", err)
		return
	}

	// Check if error is retryable
	if credentialcheck.IsRetryable(err) {
		fmt.Println("This error is retryable")
	} else {
		fmt.Println("This error is NOT retryable")
	}

	// Handle specific error types
	switch e := err.(type) {
	case *credentialcheck.AuthenticationError:
		fmt.Printf("Authentication failed: %s\n", e.Message)
		fmt.Println("Please check your API key")

	case *credentialcheck.ValidationError:
		fmt.Printf("Validation error on field '%s': %s\n", e.Field, e.Message)

	case *credentialcheck.RateLimitError:
		fmt.Printf("Rate limited. Retry after: %v\n", e.RetryAfter)

	case *credentialcheck.TimeoutError:
		fmt.Printf("Request timed out: %s\n", e.Message)
		if e.Cause != nil {
			fmt.Printf("Underlying cause: %v\n", e.Cause)
		}

	case *credentialcheck.NetworkError:
		fmt.Printf("Network error: %s\n", e.Message)
		if e.Cause != nil {
			fmt.Printf("Underlying cause: %v\n", e.Cause)
		}

	case *credentialcheck.APIError:
		fmt.Printf("API error (status %d): %s\n", e.StatusCode, e.Message)
		if e.ResponseBody != "" {
			fmt.Printf("Response body: %s\n", e.ResponseBody)
		}

	default:
		fmt.Printf("DarkStrata error: %v\n", err)
	}
}
