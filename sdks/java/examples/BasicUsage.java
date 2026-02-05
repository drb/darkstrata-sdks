import io.darkstrata.credentialcheck.*;
import io.darkstrata.credentialcheck.exception.*;

/**
 * Basic usage example for the DarkStrata Credential Check SDK.
 */
public class BasicUsage {

    public static void main(String[] args) {
        // Create a client with your API key
        try (DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(
                ClientOptions.builder("your-api-key").build()
        )) {
            // Check a single credential
            CheckResult result = client.check("user@example.com", "password123");

            if (result.isFound()) {
                System.out.println("WARNING: Credential found in breach database!");
            } else {
                System.out.println("Credential not found in any known breaches.");
            }

            // Print metadata
            CheckMetadata metadata = result.getMetadata();
            System.out.println("Hash prefix: " + metadata.getPrefix());
            System.out.println("Total results for prefix: " + metadata.getTotalResults());
            System.out.println("HMAC source: " + metadata.getHmacSource());
            System.out.println("Checked at: " + metadata.getCheckedAt());

        } catch (ValidationException e) {
            System.err.println("Validation error: " + e.getMessage());
            if (e.getField() != null) {
                System.err.println("Field: " + e.getField());
            }
        } catch (AuthenticationException e) {
            System.err.println("Authentication failed: " + e.getMessage());
        } catch (DarkStrataException e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println("Retryable: " + e.isRetryable());
        }
    }
}
