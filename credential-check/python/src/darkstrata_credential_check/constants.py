"""
Configuration constants for the DarkStrata credential check SDK.
"""

# Default base URL for the DarkStrata API.
DEFAULT_BASE_URL = "https://api.darkstrata.io/v1/"

# Default request timeout in seconds (30 seconds).
DEFAULT_TIMEOUT = 30.0

# Default number of retry attempts.
DEFAULT_RETRIES = 3

# Default cache TTL in seconds (1 hour).
# Aligned with server HMAC time window.
DEFAULT_CACHE_TTL = 3600

# Length of the hash prefix for k-anonymity queries.
PREFIX_LENGTH = 5

# Server time window duration in seconds (1 hour).
# Used for HMAC key rotation.
TIME_WINDOW_SECONDS = 3600

# API endpoint path for credential checks.
CREDENTIAL_CHECK_ENDPOINT = "credential-check/query"

# HTTP header name for API key authentication.
API_KEY_HEADER = "X-Api-Key"


class ResponseHeaders:
    """Response header names from the API."""

    PREFIX = "X-Prefix"
    HMAC_KEY = "X-HMAC-Key"
    HMAC_SOURCE = "X-HMAC-Source"
    TIME_WINDOW = "X-Time-Window"
    TOTAL_RESULTS = "X-Total-Results"
    FILTER_SINCE = "X-Filter-Since"


class RetryDefaults:
    """Retry configuration defaults."""

    INITIAL_DELAY = 1.0  # seconds
    MAX_DELAY = 10.0  # seconds
    BACKOFF_MULTIPLIER = 2


# HTTP status codes that should trigger a retry.
RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})

# SDK version for user-agent headers.
SDK_VERSION = "0.1.0"

# SDK name for user-agent headers.
SDK_NAME = "darkstrata-credential-check-python"
