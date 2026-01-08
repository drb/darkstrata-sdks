"""
DarkStrata credential check client.
"""

import asyncio
import re
import time
from datetime import datetime
from types import TracebackType
from typing import Dict, List, Literal, Optional, Type
from urllib.parse import urlencode, urljoin

import httpx

from .constants import (
    API_KEY_HEADER,
    CREDENTIAL_CHECK_ENDPOINT,
    DEFAULT_BASE_URL,
    DEFAULT_CACHE_TTL,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    RETRYABLE_STATUS_CODES,
    ResponseHeaders,
    RetryDefaults,
    SDK_NAME,
    SDK_VERSION,
    TIME_WINDOW_SECONDS,
)
from .crypto import (
    extract_prefix,
    group_by_prefix,
    hash_credential,
    HashedCredential,
    is_hash_in_set,
    is_valid_hash,
    is_valid_prefix,
)
from .errors import (
    ApiError,
    AuthenticationError,
    DarkStrataError,
    NetworkError,
    RateLimitError,
    TimeoutError,
    ValidationError,
    is_retryable_error,
)
from .types import (
    ApiResponse,
    ApiResponseHeaders,
    CacheEntry,
    CheckMetadata,
    CheckOptions,
    CheckResult,
    ClientOptions,
    Credential,
    CredentialInfo,
    ResolvedConfig,
)

# Minimum length for client-provided HMAC key (256 bits = 64 hex chars).
MIN_CLIENT_HMAC_LENGTH = 64


class DarkStrataCredentialCheck:
    """
    DarkStrata credential check client.

    This client allows you to check if credentials have been exposed in
    data breaches using k-anonymity to protect the credentials being checked.

    Example:
        >>> from darkstrata_credential_check import DarkStrataCredentialCheck
        >>>
        >>> client = DarkStrataCredentialCheck(api_key='your-api-key')
        >>>
        >>> result = await client.check('user@example.com', 'password123')
        >>> if result.found:
        ...     print('Credential found in breach database!')
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        enable_caching: bool = True,
        cache_ttl: int = DEFAULT_CACHE_TTL,
    ) -> None:
        """
        Create a new DarkStrata credential check client.

        Args:
            api_key: Your DarkStrata API key (JWT token).
            base_url: Base URL for the DarkStrata API.
                Defaults to 'https://api.darkstrata.io/v1/'.
            timeout: Request timeout in seconds. Defaults to 30.
            retries: Number of retry attempts for failed requests. Defaults to 3.
            enable_caching: Enable in-memory caching of API responses. Defaults to True.
            cache_ttl: Cache time-to-live in seconds. Defaults to 3600 (1 hour).

        Raises:
            ValidationError: If the API key is missing or invalid.

        Example:
            >>> client = DarkStrataCredentialCheck(
            ...     api_key='your-api-key',
            ...     timeout=60,  # 60 seconds
            ...     enable_caching=True,
            ... )
        """
        options = ClientOptions(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            retries=retries,
            enable_caching=enable_caching,
            cache_ttl=cache_ttl,
        )
        self._validate_options(options)

        self._config = ResolvedConfig(
            api_key=options.api_key,
            base_url=self._normalise_base_url(options.base_url),
            timeout=options.timeout,
            retries=options.retries,
            enable_caching=options.enable_caching,
            cache_ttl=options.cache_ttl,
        )

        self._cache: Dict[str, CacheEntry] = {}
        self._http_client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "DarkStrataCredentialCheck":
        """Enter async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit async context manager."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def check(
        self,
        email: str,
        password: str,
        options: Optional[CheckOptions] = None,
    ) -> CheckResult:
        """
        Check if a credential has been exposed in a data breach.

        This method uses k-anonymity to protect the credential being checked.
        Only the first 5 characters of the hash are sent to the server.

        Args:
            email: The email address or username.
            password: The password to check.
            options: Optional check options (client HMAC, date filter).

        Returns:
            A CheckResult containing whether the credential was found and metadata.

        Raises:
            ValidationError: If the email or password is empty.
            AuthenticationError: If the API key is invalid.
            ApiError: If the API request fails.

        Example:
            >>> # Basic usage
            >>> result = await client.check('user@example.com', 'password123')
            >>>
            >>> # With client-provided HMAC for deterministic results
            >>> result = await client.check('user@example.com', 'password123',
            ...     CheckOptions(client_hmac='your-256-bit-hex-key...'))
            >>>
            >>> # Filter to only breaches from 2024 onwards
            >>> result = await client.check('user@example.com', 'password123',
            ...     CheckOptions(since=datetime(2024, 1, 1)))
        """
        self._validate_credential(email, password)
        self._validate_check_options(options)

        hash_value = hash_credential(email, password)
        return await self._check_hash_internal(hash_value, email, options)

    async def check_hash(
        self,
        hash_value: str,
        options: Optional[CheckOptions] = None,
    ) -> CheckResult:
        """
        Check if a pre-computed hash has been exposed in a data breach.

        Use this method if you've already computed the SHA-256 hash of
        the credential (`email:password`).

        Args:
            hash_value: The SHA-256 hash of `email:password` (64 hex characters).
            options: Optional check options (client HMAC, date filter).

        Returns:
            A CheckResult containing whether the credential was found and metadata.

        Raises:
            ValidationError: If the hash is invalid.

        Example:
            >>> # If you've already computed the hash
            >>> hash_value = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...'
            >>> result = await client.check_hash(hash_value)
            >>>
            >>> # With options
            >>> result = await client.check_hash(hash_value,
            ...     CheckOptions(since=datetime(2024, 1, 1)))
        """
        normalised_hash = hash_value.upper()

        if not is_valid_hash(normalised_hash):
            raise ValidationError(
                "Invalid hash format. Expected 64 hexadecimal characters.",
                field="hash",
            )

        self._validate_check_options(options)

        return await self._check_hash_internal(normalised_hash, None, options)

    async def check_batch(
        self,
        credentials: List[Credential],
        options: Optional[CheckOptions] = None,
    ) -> List[CheckResult]:
        """
        Check multiple credentials in a single batch.

        Credentials are grouped by their hash prefix to minimise API calls.

        Args:
            credentials: List of credential objects to check.
            options: Optional check options applied to all credentials.

        Returns:
            A list of CheckResult objects, one for each credential.

        Raises:
            ValidationError: If any credential is invalid.

        Example:
            >>> results = await client.check_batch([
            ...     Credential(email='user1@example.com', password='pass1'),
            ...     Credential(email='user2@example.com', password='pass2'),
            ... ])
            >>>
            >>> # With date filter applied to all credentials
            >>> results = await client.check_batch(credentials,
            ...     CheckOptions(since=datetime(2024, 1, 1)))
            >>>
            >>> for result in results:
            ...     if result.found:
            ...         print(f'{result.credential.email} was compromised!')
        """
        if not credentials:
            return []

        # Validate all credentials first
        for credential in credentials:
            self._validate_credential(credential.email, credential.password)
        self._validate_check_options(options)

        # Hash all credentials and group by prefix
        hashed_credentials = [
            HashedCredential(
                email=cred.email,
                password=cred.password,
                hash_value=hash_credential(cred.email, cred.password),
            )
            for cred in credentials
        ]

        grouped_by_prefix = group_by_prefix(hashed_credentials)

        # Fetch data for each unique prefix
        prefix_responses: Dict[str, ApiResponse] = {}

        async def fetch_prefix(prefix: str) -> None:
            response = await self._fetch_prefix_data(prefix, options)
            prefix_responses[prefix] = response

        # Fetch all prefixes concurrently
        await asyncio.gather(*[fetch_prefix(prefix) for prefix in grouped_by_prefix.keys()])

        # Check each credential against its prefix's response
        results: List[CheckResult] = []

        for hashed_cred in hashed_credentials:
            prefix = extract_prefix(hashed_cred.hash)
            response = prefix_responses.get(prefix)

            if response is None:
                # This shouldn't happen, but handle gracefully
                results.append(
                    self._create_check_result(
                        found=False,
                        email=hashed_cred.email,
                        metadata=CheckMetadata(
                            prefix=prefix,
                            total_results=0,
                            hmac_source="server",
                            cached_result=False,
                            checked_at=datetime.now(),
                        ),
                    )
                )
                continue

            found = is_hash_in_set(
                hashed_cred.hash,
                response.headers.hmac_key,
                response.hashes,
            )

            results.append(
                self._create_check_result(
                    found=found,
                    email=hashed_cred.email,
                    metadata=CheckMetadata(
                        prefix=prefix,
                        total_results=response.headers.total_results,
                        hmac_source=response.headers.hmac_source,
                        time_window=response.headers.time_window,
                        filter_since=response.headers.filter_since,
                        cached_result=False,  # Batch doesn't use caching for individual results
                        checked_at=datetime.now(),
                    ),
                )
            )

        return results

    def clear_cache(self) -> None:
        """
        Clear the internal cache.

        Example:
            >>> client.clear_cache()
        """
        self._cache.clear()

    def get_cache_size(self) -> int:
        """
        Get the current cache size.

        Returns:
            The number of entries in the cache.
        """
        return len(self._cache)

    # ============================================================
    # Private methods
    # ============================================================

    def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=self._config.timeout,
                headers={
                    API_KEY_HEADER: self._config.api_key,
                    "User-Agent": f"{SDK_NAME}/{SDK_VERSION}",
                    "Accept": "application/json",
                },
            )
        return self._http_client

    async def _check_hash_internal(
        self,
        hash_value: str,
        email: Optional[str],
        options: Optional[CheckOptions],
    ) -> CheckResult:
        """Internal method to check a hash."""
        prefix = extract_prefix(hash_value)
        response = await self._fetch_prefix_data(prefix, options)

        found = is_hash_in_set(hash_value, response.headers.hmac_key, response.hashes)

        return self._create_check_result(
            found=found,
            email=email,
            metadata=CheckMetadata(
                prefix=prefix,
                total_results=response.headers.total_results,
                hmac_source=response.headers.hmac_source,
                time_window=response.headers.time_window,
                filter_since=response.headers.filter_since,
                cached_result=False,  # TODO: Track this properly
                checked_at=datetime.now(),
            ),
        )

    async def _fetch_prefix_data(
        self,
        prefix: str,
        options: Optional[CheckOptions],
    ) -> ApiResponse:
        """Fetch data for a prefix from the API or cache."""
        # Don't use cache when client provides custom options
        # (client_hmac or since would change the response)
        use_cache = (
            self._config.enable_caching
            and (options is None or options.client_hmac is None)
            and (options is None or options.since is None)
        )

        # Check cache first
        if use_cache:
            cached = self._get_cached_response(prefix)
            if cached is not None:
                return cached

        # Fetch from API
        response = await self._fetch_with_retry(prefix, options)

        # Cache the response (only if no custom options and server HMAC)
        if use_cache and response.headers.time_window is not None:
            self._cache_response(prefix, response, response.headers.time_window)

        return response

    async def _fetch_with_retry(
        self,
        prefix: str,
        options: Optional[CheckOptions],
    ) -> ApiResponse:
        """Fetch with retry logic."""
        last_error: Optional[Exception] = None
        delay = RetryDefaults.INITIAL_DELAY

        for attempt in range(self._config.retries + 1):
            try:
                return await self._fetch(prefix, options)
            except Exception as error:
                last_error = error

                if not is_retryable_error(error) or attempt == self._config.retries:
                    raise

                # Wait before retrying
                await asyncio.sleep(delay)
                delay = min(delay * RetryDefaults.BACKOFF_MULTIPLIER, RetryDefaults.MAX_DELAY)

        raise last_error or Exception("Unknown error during fetch")

    async def _fetch(
        self,
        prefix: str,
        options: Optional[CheckOptions],
    ) -> ApiResponse:
        """Perform the actual API request."""
        if not is_valid_prefix(prefix):
            raise ValidationError(f"Invalid prefix: {prefix}", field="prefix")

        # Build URL with query parameters
        url = urljoin(self._config.base_url, CREDENTIAL_CHECK_ENDPOINT)
        params: Dict[str, str] = {"prefix": prefix}

        if options is not None:
            if options.client_hmac is not None:
                params["clientHmac"] = options.client_hmac

            if options.since is not None:
                since_value = self._convert_to_since_param(options.since)
                params["since"] = str(since_value)

        full_url = f"{url}?{urlencode(params)}"

        try:
            client = self._get_http_client()
            response = await client.get(full_url)
            return await self._handle_response(response)

        except httpx.TimeoutException as error:
            raise TimeoutError(self._config.timeout, cause=error) from error

        except httpx.RequestError as error:
            raise NetworkError(str(error), cause=error) from error

        except DarkStrataError:
            raise

        except Exception as error:
            raise NetworkError(f"Unknown network error: {error}", cause=error) from error

    async def _handle_response(self, response: httpx.Response) -> ApiResponse:
        """Handle the API response."""
        if response.status_code == 401:
            raise AuthenticationError()

        if response.status_code == 429:
            retry_after_header = response.headers.get("Retry-After")
            retry_after = int(retry_after_header) if retry_after_header else None
            raise RateLimitError(retry_after)

        if not response.is_success:
            is_retryable = response.status_code in RETRYABLE_STATUS_CODES

            try:
                response_body = response.json()
            except Exception:
                response_body = response.text

            raise ApiError(
                f"API request failed with status {response.status_code}",
                response.status_code,
                response_body=response_body,
                retryable=is_retryable,
            )

        # Parse response headers
        headers = self._parse_response_headers(response)

        # Parse response body
        hashes: List[str] = response.json()

        return ApiResponse(hashes=hashes, headers=headers)

    def _parse_response_headers(self, response: httpx.Response) -> ApiResponseHeaders:
        """Parse the response headers."""
        prefix = response.headers.get(ResponseHeaders.PREFIX, "")
        hmac_key = response.headers.get(ResponseHeaders.HMAC_KEY, "")
        hmac_source_raw = response.headers.get(ResponseHeaders.HMAC_SOURCE)
        hmac_source: Literal["server", "client"] = (
            "client" if hmac_source_raw == "client" else "server"
        )
        time_window_raw = response.headers.get(ResponseHeaders.TIME_WINDOW)
        total_results_raw = response.headers.get(ResponseHeaders.TOTAL_RESULTS)
        filter_since_raw = response.headers.get(ResponseHeaders.FILTER_SINCE)

        return ApiResponseHeaders(
            prefix=prefix,
            hmac_key=hmac_key,
            hmac_source=hmac_source,
            time_window=int(time_window_raw) if time_window_raw else None,
            total_results=int(total_results_raw) if total_results_raw else 0,
            filter_since=int(filter_since_raw) if filter_since_raw else None,
        )

    def _get_cached_response(self, prefix: str) -> Optional[ApiResponse]:
        """Get a cached response if available and valid."""
        current_time_window = self._get_current_time_window()
        cache_key = f"{prefix}:{current_time_window}"
        entry = self._cache.get(cache_key)

        if entry is None:
            return None

        # Check if cache entry is still valid
        now = time.time()
        if now - entry.created_at > self._config.cache_ttl:
            del self._cache[cache_key]
            return None

        # Check if time window has changed
        if entry.time_window != current_time_window:
            del self._cache[cache_key]
            return None

        return entry.response

    def _cache_response(
        self,
        prefix: str,
        response: ApiResponse,
        time_window: int,
    ) -> None:
        """Cache a response."""
        cache_key = f"{prefix}:{time_window}"
        self._cache[cache_key] = CacheEntry(
            response=response,
            time_window=time_window,
            created_at=time.time(),
        )

        # Clean up old cache entries
        self._prune_cache()

    def _prune_cache(self) -> None:
        """Remove expired cache entries."""
        current_time_window = self._get_current_time_window()
        now = time.time()

        keys_to_delete = []
        for key, entry in self._cache.items():
            # Remove entries from old time windows
            if entry.time_window != current_time_window:
                keys_to_delete.append(key)
                continue

            # Remove expired entries
            if now - entry.created_at > self._config.cache_ttl:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self._cache[key]

    def _get_current_time_window(self) -> int:
        """Get the current time window."""
        return int(time.time() // TIME_WINDOW_SECONDS)

    def _create_check_result(
        self,
        found: bool,
        email: Optional[str],
        metadata: CheckMetadata,
    ) -> CheckResult:
        """Create a check result."""
        return CheckResult(
            found=found,
            credential=CredentialInfo(
                email=email if email is not None else "[hash-only]",
                masked=True,
            ),
            metadata=metadata,
        )

    def _validate_options(self, options: ClientOptions) -> None:
        """Validate client options."""
        if not options.api_key or not isinstance(options.api_key, str):
            raise ValidationError("API key is required", field="api_key")

        if options.api_key.strip() == "":
            raise ValidationError("API key cannot be empty", field="api_key")

        if options.timeout <= 0:
            raise ValidationError("Timeout must be a positive number", field="timeout")

        if options.retries < 0:
            raise ValidationError("Retries must be a non-negative number", field="retries")

        if options.cache_ttl <= 0:
            raise ValidationError("Cache TTL must be a positive number", field="cache_ttl")

    def _validate_credential(self, email: str, password: str) -> None:
        """Validate a credential."""
        if not email or not isinstance(email, str) or email.strip() == "":
            raise ValidationError("Email is required", field="email")

        if not password or not isinstance(password, str) or password == "":
            raise ValidationError("Password is required", field="password")

    def _validate_check_options(self, options: Optional[CheckOptions]) -> None:
        """Validate check options."""
        if options is None:
            return

        # Validate client_hmac if provided
        if options.client_hmac is not None:
            if not isinstance(options.client_hmac, str):
                raise ValidationError("Client HMAC must be a string", field="client_hmac")

            if len(options.client_hmac) < MIN_CLIENT_HMAC_LENGTH:
                raise ValidationError(
                    f"Client HMAC must be at least {MIN_CLIENT_HMAC_LENGTH} "
                    "hexadecimal characters (256 bits)",
                    field="client_hmac",
                )

            if not re.match(r"^[A-Fa-f0-9]+$", options.client_hmac):
                raise ValidationError(
                    "Client HMAC must be a hexadecimal string",
                    field="client_hmac",
                )

        # Validate since if provided
        if options.since is not None:
            if isinstance(options.since, datetime):
                # datetime objects are valid
                pass
            elif isinstance(options.since, int):
                if options.since < 0:
                    raise ValidationError(
                        "Since parameter must be a positive integer "
                        "(epoch day or Unix timestamp)",
                        field="since",
                    )
            else:
                raise ValidationError(
                    "Since parameter must be a datetime or integer",
                    field="since",
                )

    def _convert_to_since_param(self, since: int | datetime) -> int:
        """Convert since parameter to API format."""
        if isinstance(since, datetime):
            # Convert datetime to epoch day (days since 1 January 1970)
            return int(since.timestamp() // 86400)

        # Already a number - could be epoch day or Unix timestamp
        # The API auto-detects based on value (>100000 = timestamp)
        return since

    def _normalise_base_url(self, url: str) -> str:
        """Ensure URL ends with a slash."""
        return url if url.endswith("/") else f"{url}/"
