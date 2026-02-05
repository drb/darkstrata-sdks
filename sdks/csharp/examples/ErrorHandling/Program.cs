using DarkStrata.CredentialCheck;

// Get API key from environment variable (use invalid key for demo)
var apiKey = Environment.GetEnvironmentVariable("DARKSTRATA_API_KEY") ?? "invalid-key-for-demo";

Console.WriteLine("DarkStrata Credential Check - Error Handling Example");
Console.WriteLine("=====================================================\n");

// Example 1: Validation Errors
Console.WriteLine("1. Validation Errors");
Console.WriteLine("--------------------");

try
{
    using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = "" });
}
catch (ValidationException ex)
{
    Console.WriteLine($"  ValidationException caught:");
    Console.WriteLine($"    Message: {ex.Message}");
    Console.WriteLine($"    Field: {ex.Field}");
    Console.WriteLine($"    Code: {ex.Code}");
    Console.WriteLine($"    Retryable: {ex.IsRetryable}");
}

Console.WriteLine();

// Example 2: Using type guards
Console.WriteLine("2. Exception Type Checking");
Console.WriteLine("--------------------------");

try
{
    using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = apiKey });
    await client.CheckAsync("test@example.com", "password");
}
catch (DarkStrataException ex)
{
    Console.WriteLine($"  Caught DarkStrataException:");
    Console.WriteLine($"    Type: {ex.GetType().Name}");
    Console.WriteLine($"    Message: {ex.Message}");
    Console.WriteLine($"    Code: {ex.Code}");
    Console.WriteLine($"    StatusCode: {ex.StatusCode}");
    Console.WriteLine($"    Retryable: {ex.IsRetryable}");

    // Handle specific error types
    switch (ex)
    {
        case AuthenticationException:
            Console.WriteLine("    -> Check your API key");
            break;
        case RateLimitException rle:
            Console.WriteLine($"    -> Wait {rle.RetryAfter ?? 60} seconds before retrying");
            break;
        case DarkStrataTimeoutException te:
            Console.WriteLine($"    -> Request timed out after {te.TimeoutMs}ms");
            break;
        case NetworkException:
            Console.WriteLine("    -> Check your network connection");
            break;
        case ApiException ae:
            Console.WriteLine($"    -> API error: {ae.ResponseBody ?? "No response body"}");
            break;
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  Unexpected error: {ex.Message}");
}

Console.WriteLine();

// Example 3: Retry logic based on IsRetryable
Console.WriteLine("3. Retry Logic Example");
Console.WriteLine("----------------------");

async Task<CheckResult?> CheckWithRetryAsync(DarkStrataCredentialCheck client, string email, string password)
{
    const int maxAttempts = 3;

    for (var attempt = 1; attempt <= maxAttempts; attempt++)
    {
        try
        {
            Console.WriteLine($"  Attempt {attempt}...");
            return await client.CheckAsync(email, password);
        }
        catch (DarkStrataException ex) when (ex.IsRetryable && attempt < maxAttempts)
        {
            Console.WriteLine($"    Retryable error: {ex.Message}");
            var delay = (int)Math.Pow(2, attempt) * 1000; // Exponential backoff
            Console.WriteLine($"    Waiting {delay}ms before retry...");
            await Task.Delay(delay);
        }
        catch (DarkStrataException ex) when (!ex.IsRetryable)
        {
            Console.WriteLine($"    Non-retryable error: {ex.Message}");
            throw;
        }
    }

    return null;
}

try
{
    using var client = new DarkStrataCredentialCheck(new ClientOptions
    {
        ApiKey = apiKey,
        Timeout = TimeSpan.FromSeconds(5)
    });

    var result = await CheckWithRetryAsync(client, "test@example.com", "password");
    Console.WriteLine($"  Result: {(result?.Found == true ? "Found" : "Not found")}");
}
catch (Exception ex)
{
    Console.WriteLine($"  Final error: {ex.Message}");
}

Console.WriteLine();

// Example 4: Checking error codes
Console.WriteLine("4. Error Code Handling");
Console.WriteLine("----------------------");

void HandleError(DarkStrataException ex)
{
    Console.WriteLine($"  Error code: {ex.Code}");

    var action = ex.Code switch
    {
        ErrorCode.AuthenticationError => "Verify your API key in the dashboard",
        ErrorCode.ValidationError => "Check your input parameters",
        ErrorCode.RateLimitError => "Reduce request frequency or upgrade your plan",
        ErrorCode.TimeoutError => "Increase timeout or check network latency",
        ErrorCode.NetworkError => "Check your internet connection",
        ErrorCode.ApiError => "Contact support if the issue persists",
        _ => "Unknown error"
    };

    Console.WriteLine($"  Recommended action: {action}");
}

try
{
    using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = apiKey });
    await client.CheckAsync("test@example.com", "password");
}
catch (DarkStrataException ex)
{
    HandleError(ex);
}

Console.WriteLine("\nDone!");
