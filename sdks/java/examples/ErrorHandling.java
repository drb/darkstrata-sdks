import io.darkstrata.credentialcheck.*;
import io.darkstrata.credentialcheck.exception.*;

/**
 * Error handling example for the DarkStrata Credential Check SDK.
 */
public class ErrorHandling {

    public static void main(String[] args) {
        try (DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(
                ClientOptions.builder("your-api-key")
                        .retries(3) // Retry up to 3 times on transient failures
                        .timeout(30000) // 30 second timeout
                        .build()
        )) {
            CheckResult result = client.check("user@example.com", "password123");
            System.out.println("Found: " + result.isFound());

        } catch (ValidationException e) {
            // Input validation failed
            System.err.println("Invalid input: " + e.getMessage());
            if (e.getField() != null) {
                System.err.println("Problem with field: " + e.getField());
            }

        } catch (AuthenticationException e) {
            // API key is invalid or missing
            System.err.println("Authentication failed: " + e.getMessage());
            System.err.println("Please check your API key.");

        } catch (RateLimitException e) {
            // Rate limited by the API
            System.err.println("Rate limited!");
            if (e.getRetryAfter() != null) {
                System.err.println("Retry after " + e.getRetryAfter() + " seconds");
            }

        } catch (TimeoutException e) {
            // Request timed out
            System.err.println("Request timed out after " + e.getTimeoutMs() + "ms");
            System.err.println("This error is retryable: " + e.isRetryable());

        } catch (NetworkException e) {
            // Network connectivity issue
            System.err.println("Network error: " + e.getMessage());
            System.err.println("This error is retryable: " + e.isRetryable());

        } catch (ApiException e) {
            // API returned an error response
            System.err.println("API error (status " + e.getStatusCode() + "): " + e.getMessage());
            if (e.getResponseBody() != null) {
                System.err.println("Response body: " + e.getResponseBody());
            }
            System.err.println("This error is retryable: " + e.isRetryable());

        } catch (DarkStrataException e) {
            // Catch-all for any other DarkStrata errors
            System.err.println("Error (code: " + e.getCode() + "): " + e.getMessage());
            System.err.println("Retryable: " + e.isRetryable());

            // Check if we should retry
            if (DarkStrataException.isRetryableError(e)) {
                System.out.println("This error can be retried.");
            }
        }
    }
}
