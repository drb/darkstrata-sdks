import io.darkstrata.credentialcheck.*;
import io.darkstrata.credentialcheck.exception.*;

import java.util.Arrays;
import java.util.List;

/**
 * Batch checking example for the DarkStrata Credential Check SDK.
 */
public class BatchCheck {

    public static void main(String[] args) {
        try (DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(
                ClientOptions.builder("your-api-key")
                        .timeout(60000) // 60 second timeout for batch operations
                        .build()
        )) {
            // Create a batch of credentials to check
            List<Credential> credentials = Arrays.asList(
                    new Credential("user1@example.com", "password123"),
                    new Credential("user2@example.com", "secretpass"),
                    new Credential("admin@example.com", "admin123"),
                    new Credential("test@example.com", "testpass")
            );

            // Check all credentials in a single batch operation
            List<CheckResult> results = client.checkBatch(credentials);

            // Process results
            int compromisedCount = 0;
            for (int i = 0; i < results.size(); i++) {
                CheckResult result = results.get(i);
                Credential cred = credentials.get(i);

                if (result.isFound()) {
                    compromisedCount++;
                    System.out.println("COMPROMISED: " + cred.getEmail());
                } else {
                    System.out.println("Safe: " + cred.getEmail());
                }
            }

            System.out.println("\nSummary:");
            System.out.println("Total checked: " + credentials.size());
            System.out.println("Compromised: " + compromisedCount);
            System.out.println("Safe: " + (credentials.size() - compromisedCount));

        } catch (DarkStrataException e) {
            System.err.println("Error during batch check: " + e.getMessage());
        }
    }
}
