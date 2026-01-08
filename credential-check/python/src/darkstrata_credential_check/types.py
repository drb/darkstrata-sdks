"""
Type definitions for the DarkStrata credential check SDK.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Literal, Optional, Union

from .constants import (
    DEFAULT_BASE_URL,
    DEFAULT_CACHE_TTL,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
)


@dataclass
class ClientOptions:
    """
    Configuration options for the DarkStrata credential check client.

    Attributes:
        api_key: Your DarkStrata API key (JWT token).
            Obtain this from your DarkStrata dashboard.
        base_url: Base URL for the DarkStrata API.
            Defaults to 'https://api.darkstrata.io/v1/'.
        timeout: Request timeout in seconds.
            Defaults to 30.
        retries: Number of retry attempts for failed requests.
            Defaults to 3.
        enable_caching: Enable in-memory caching of API responses.
            Cache is automatically invalidated when the server time window changes.
            Defaults to True.
        cache_ttl: Cache time-to-live in seconds.
            Should align with server time window (1 hour).
            Defaults to 3600.
    """

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    enable_caching: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL


@dataclass
class Credential:
    """
    A credential pair to check.

    Attributes:
        email: The email address or username.
        password: The password to check.
    """

    email: str
    password: str


@dataclass
class CheckOptions:
    """
    Options for individual credential check requests.

    Attributes:
        client_hmac: Client-provided HMAC key for deterministic results.
            When provided, results are consistent across requests (not time-windowed).
            Must be a cryptographically strong hex string of at least 64 characters (256 bits).

            Use this when you need:
            - Consistent results across multiple requests
            - To avoid server-side HMAC key rotation
            - Custom key management

        since: Filter results to only include breaches from this date onwards.
            Accepts either:
            - Epoch day: Days since 1 January 1970 (e.g., 19724 = 1 January 2024)
            - Unix timestamp: Seconds since 1 January 1970 (auto-detected if > 100000)
            - datetime object: Will be converted to epoch day
    """

    client_hmac: Optional[str] = None
    since: Optional[Union[int, datetime]] = None


@dataclass
class CredentialInfo:
    """
    Information about the credential that was checked.

    Attributes:
        email: The email address that was checked.
        masked: Always True - the password is never included in results.
    """

    email: str
    masked: Literal[True] = True


@dataclass
class CheckMetadata:
    """
    Metadata returned with check results.

    Attributes:
        prefix: The 5-character hash prefix used for the k-anonymity lookup.
        total_results: Total number of matching hashes returned by the API.
        hmac_source: Source of the HMAC key used for this request.
            'server': Server-generated key (rotates hourly).
            'client': Client-provided key (deterministic).
        time_window: Server time window (hour-based) for HMAC key rotation.
            Only present when using server-generated HMAC.
        filter_since: The epoch day used for filtering (if `since` was provided).
            Epoch day = days since 1 January 1970.
        cached_result: Whether this result was served from cache.
        checked_at: Timestamp when the check was performed.
    """

    prefix: str
    total_results: int
    hmac_source: Literal["server", "client"]
    cached_result: bool
    checked_at: datetime
    time_window: Optional[int] = None
    filter_since: Optional[int] = None


@dataclass
class CheckResult:
    """
    Result of a credential check.

    Attributes:
        found: Whether the credential was found in a data breach.
            True means the credential has been compromised.
        credential: Information about the credential that was checked.
        metadata: Additional metadata about the check.
    """

    found: bool
    credential: CredentialInfo
    metadata: CheckMetadata


@dataclass
class ApiResponseHeaders:
    """
    Response headers from the k-anonymity API.

    Internal use only.

    Attributes:
        prefix: The normalised prefix that was queried.
        hmac_key: The HMAC key used to encode the results.
        hmac_source: Source of the HMAC key ('server' or 'client').
        total_results: Total number of results.
        time_window: Server time window (only present for server-generated HMAC).
        filter_since: Filter epoch day (if since parameter was used).
    """

    prefix: str
    hmac_key: str
    hmac_source: Literal["server", "client"]
    total_results: int
    time_window: Optional[int] = None
    filter_since: Optional[int] = None


@dataclass
class ApiResponse:
    """
    Raw API response from the k-anonymity endpoint.

    Internal use only.

    Attributes:
        hashes: Array of HMAC'd hash suffixes.
        headers: Response headers from the API.
    """

    hashes: List[str]
    headers: ApiResponseHeaders


@dataclass
class RetryPolicy:
    """
    Retry policy configuration.

    Attributes:
        max_retries: Maximum number of retry attempts. Defaults to 3.
        initial_delay: Initial delay between retries in seconds. Defaults to 1.0.
        max_delay: Maximum delay between retries in seconds. Defaults to 10.0.
        backoff_multiplier: Multiplier for exponential backoff. Defaults to 2.
    """

    max_retries: int = 3
    initial_delay: float = 1.0
    max_delay: float = 10.0
    backoff_multiplier: int = 2


@dataclass
class CacheEntry:
    """
    Cache entry structure.

    Internal use only.

    Attributes:
        response: Cached API response.
        time_window: Time window when this entry was cached.
        created_at: Timestamp when this entry was created (Unix timestamp).
    """

    response: ApiResponse
    time_window: int
    created_at: float


@dataclass
class ResolvedConfig:
    """
    Internal resolved configuration with all defaults applied.

    Internal use only.
    """

    api_key: str
    base_url: str
    timeout: float
    retries: int
    enable_caching: bool
    cache_ttl: int
