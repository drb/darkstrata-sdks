using DarkStrata.CredentialCheck;

// Parse command-line arguments
if (args.Length < 2)
{
    Console.WriteLine("Usage: dotnet run -- <email> <password>");
    Console.WriteLine("Example: dotnet run -- user@example.com mypassword123");
    Console.WriteLine("\nNote: DARKSTRATA_API_KEY environment variable must be set.");
    Environment.Exit(1);
}

var email = args[0];
var password = args[1];

// Get API key from environment variable
var apiKey = Environment.GetEnvironmentVariable("DARKSTRATA_API_KEY")
    ?? throw new InvalidOperationException("DARKSTRATA_API_KEY environment variable is required");

// Create client
using var client = new DarkStrataCredentialCheck(new ClientOptions
{
    ApiKey = apiKey
});

Console.WriteLine("DarkStrata Credential Check - Basic Usage Example");
Console.WriteLine("==================================================\n");

Console.WriteLine($"Checking credential: {email}");

try
{
    var result = await client.CheckAsync(email, password);

    Console.WriteLine($"\nResult:");
    Console.WriteLine($"  Found: {result.Found}");
    Console.WriteLine($"  Email: {result.Email}");
    Console.WriteLine($"  Masked: {result.Masked}");
    Console.WriteLine($"\nMetadata:");
    Console.WriteLine($"  Prefix: {result.Metadata.Prefix}");
    Console.WriteLine($"  Total Results: {result.Metadata.TotalResults}");
    Console.WriteLine($"  HMAC Source: {result.Metadata.HmacSource}");
    Console.WriteLine($"  Time Window: {result.Metadata.TimeWindow}");
    Console.WriteLine($"  Cached: {result.Metadata.CachedResult}");
    Console.WriteLine($"  Checked At: {result.Metadata.CheckedAt}");

    if (result.Found)
    {
        Console.WriteLine("\n[WARNING] This credential was found in a data breach!");
        Console.WriteLine("          You should change this password immediately.");
    }
    else
    {
        Console.WriteLine("\n[OK] This credential was not found in our breach database.");
    }
}
catch (AuthenticationException)
{
    Console.WriteLine("Error: Invalid API key");
    Environment.Exit(1);
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
    Environment.Exit(1);
}
