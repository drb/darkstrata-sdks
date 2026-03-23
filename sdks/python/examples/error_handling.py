"""
Error handling example for darkstrata-credential-check

This example demonstrates how to handle various error scenarios
when using the SDK.

Run: python examples/error_handling.py
"""

import asyncio
import os

from darkstrata_credential_check import (
    ApiError,
    AuthenticationError,
    DarkStrataCredentialCheck,
    NetworkError,
    RateLimitError,
    TimeoutError,
    ValidationError,
    is_darkstrata_error,
)


async def main() -> None:
    # Example 1: Handling validation errors
    print("Example 1: Validation Error")
    print("---")

    try:
        client = DarkStrataCredentialCheck(api_key="")  # Empty API key - will throw ValidationError
        await client.check("user@example.com", "password")
    except ValidationError as error:
        print(f'Validation error on field "{error.field}": {error}')

    print("")

    # Example 2: Handling authentication errors
    print("Example 2: Authentication Error")
    print("---")

    try:
        async with DarkStrataCredentialCheck(api_key="invalid-api-key") as client:
            await client.check("user@example.com", "password")
    except AuthenticationError as error:
        print(f"Authentication failed: {error}")
        print("Please check your API key.")

    print("")

    # Example 3: Comprehensive error handling
    print("Example 3: Comprehensive Error Handling")
    print("---")

    api_key = os.environ.get("DARKSTRATA_API_KEY", "your-api-key")

    async with DarkStrataCredentialCheck(
        api_key=api_key,
        timeout=5.0,  # 5 second timeout
        retries=2,
    ) as client:
        try:
            result = await client.check("user@example.com", "password")
            print(f"Check completed. Found: {result.found}")
        except AuthenticationError:
            # 401 - Invalid API key
            print("Authentication failed. Check your API key.")
        except ValidationError as error:
            # Invalid input
            print(f"Invalid input: {error}")
        except RateLimitError as error:
            # 429 - Too many requests
            if error.retry_after:
                print(f"Rate limited. Retry after {error.retry_after} seconds.")
            else:
                print("Rate limited. Please slow down requests.")
        except TimeoutError as error:
            # Request timed out
            print(f"Request timed out after {error.timeout_seconds}s.")
            print("Consider increasing the timeout setting.")
        except NetworkError as error:
            # Network connectivity issue
            print(f"Network error: {error}")
            print("Check your internet connection.")
        except ApiError as error:
            # Other API errors
            print(f"API error ({error.status_code}): {error}")
            if error.retryable:
                print("This error is retryable.")
        except Exception as error:
            if is_darkstrata_error(error):
                # Generic DarkStrata error
                print(f"DarkStrata error [{error.code}]: {error}")
            else:
                # Unknown error
                raise

    print("")

    # Example 4: Checking if errors are retryable
    print("Example 4: Retryable Errors")
    print("---")

    error_examples = [
        AuthenticationError(),
        ValidationError("Invalid email"),
        TimeoutError(5.0),
        NetworkError("Connection refused"),
        RateLimitError(60),
        ApiError("Server error", 500, retryable=True),
        ApiError("Not found", 404, retryable=False),
    ]

    for error in error_examples:
        print(f"{error.__class__.__name__}: retryable = {error.retryable}")


if __name__ == "__main__":
    asyncio.run(main())
