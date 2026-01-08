"""Tests for DarkStrataCredentialCheck client."""

import pytest
import httpx
import respx

from darkstrata_credential_check import (
    DarkStrataCredentialCheck,
    AuthenticationError,
    ValidationError,
    ApiError,
    RateLimitError,
    Credential,
    CheckOptions,
)
from darkstrata_credential_check.crypto import hash_credential, hmac_sha256


API_KEY = "test-api-key"
BASE_URL = "https://api.test.com/v1/"


class TestConstructor:
    """Tests for constructor."""

    def test_should_create_client_with_valid_options(self) -> None:
        """Should create client with valid options."""
        client = DarkStrataCredentialCheck(api_key=API_KEY)
        assert isinstance(client, DarkStrataCredentialCheck)

    def test_should_raise_validation_error_for_missing_api_key(self) -> None:
        """Should raise ValidationError for missing API key."""
        with pytest.raises(ValidationError):
            DarkStrataCredentialCheck(api_key="")

    def test_should_raise_validation_error_for_whitespace_only_api_key(self) -> None:
        """Should raise ValidationError for whitespace-only API key."""
        with pytest.raises(ValidationError):
            DarkStrataCredentialCheck(api_key="   ")

    def test_should_raise_validation_error_for_invalid_timeout(self) -> None:
        """Should raise ValidationError for invalid timeout."""
        with pytest.raises(ValidationError):
            DarkStrataCredentialCheck(api_key=API_KEY, timeout=0)

        with pytest.raises(ValidationError):
            DarkStrataCredentialCheck(api_key=API_KEY, timeout=-1)

    def test_should_raise_validation_error_for_invalid_retries(self) -> None:
        """Should raise ValidationError for invalid retries."""
        with pytest.raises(ValidationError):
            DarkStrataCredentialCheck(api_key=API_KEY, retries=-1)

    def test_should_raise_validation_error_for_invalid_cache_ttl(self) -> None:
        """Should raise ValidationError for invalid cacheTTL."""
        with pytest.raises(ValidationError):
            DarkStrataCredentialCheck(api_key=API_KEY, cache_ttl=0)

    def test_should_accept_custom_base_url(self) -> None:
        """Should accept custom baseUrl."""
        client = DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url="https://custom.api.com",
        )
        assert isinstance(client, DarkStrataCredentialCheck)


class TestCheck:
    """Tests for check method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_return_found_true_when_credential_in_breach_database(self) -> None:
        """Should return found: true when credential is in breach database."""
        email = "test@example.com"
        password = "password123"
        credential_hash = hash_credential(email, password)
        hmac_key = "a" * 64
        expected_hmac = hmac_sha256(credential_hash, hmac_key)

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[expected_hmac],
                headers={
                    "X-Prefix": credential_hash[:5],
                    "X-HMAC-Key": hmac_key,
                    "X-HMAC-Source": "server",
                    "X-Time-Window": "12345",
                    "X-Total-Results": "1",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check(email, password)

            assert result.found is True
            assert result.credential.email == email
            assert result.credential.masked is True
            assert result.metadata.prefix == credential_hash[:5]
            assert result.metadata.total_results == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_return_found_false_when_credential_not_in_breach_database(self) -> None:
        """Should return found: false when credential is not in breach database."""
        email = "safe@example.com"
        password = "safePassword"
        hmac_key = "b" * 64

        # Return hashes that don't match the credential
        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[
                    hmac_sha256("C" * 64, hmac_key),
                    hmac_sha256("D" * 64, hmac_key),
                ],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": hmac_key,
                    "X-HMAC-Source": "server",
                    "X-Time-Window": "12345",
                    "X-Total-Results": "2",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check(email, password)

            assert result.found is False
            assert result.credential.email == email

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_for_empty_email(self) -> None:
        """Should raise ValidationError for empty email."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            with pytest.raises(ValidationError):
                await client.check("", "password")

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_for_empty_password(self) -> None:
        """Should raise ValidationError for empty password."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            with pytest.raises(ValidationError):
                await client.check("email@test.com", "")

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_raise_authentication_error_for_401_response(self) -> None:
        """Should raise AuthenticationError for 401 response."""
        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                401,
                json={"message": "Unauthorized"},
            )
        )

        async with DarkStrataCredentialCheck(
            api_key="invalid-key",
            base_url=BASE_URL,
            retries=0,
        ) as client:
            with pytest.raises(AuthenticationError):
                await client.check("email@test.com", "password")

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_raise_rate_limit_error_for_429_response(self) -> None:
        """Should raise RateLimitError for 429 response."""
        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                429,
                json={"message": "Rate limited"},
                headers={"Retry-After": "60"},
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            retries=0,
        ) as client:
            with pytest.raises(RateLimitError):
                await client.check("email@test.com", "password")

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_raise_api_error_for_other_error_responses(self) -> None:
        """Should raise ApiError for other error responses."""
        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                500,
                json={"message": "Server error"},
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            retries=0,
        ) as client:
            with pytest.raises(ApiError):
                await client.check("email@test.com", "password")


class TestCheckHash:
    """Tests for checkHash method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_accept_valid_hash_and_return_result(self) -> None:
        """Should accept valid hash and return result."""
        hash_value = "A" * 64
        hmac_key = "c" * 64
        expected_hmac = hmac_sha256(hash_value, hmac_key)

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[expected_hmac],
                headers={
                    "X-Prefix": "AAAAA",
                    "X-HMAC-Key": hmac_key,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "1",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check_hash(hash_value)

            assert result.found is True
            assert result.credential.email == "[hash-only]"

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_normalise_lowercase_hash_to_uppercase(self) -> None:
        """Should normalise lowercase hash to uppercase."""
        hash_value = "a" * 64  # lowercase
        hmac_key = "d" * 64

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "AAAAA",
                    "X-HMAC-Key": hmac_key,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "0",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check_hash(hash_value)

            assert result.found is False

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_for_invalid_hash(self) -> None:
        """Should raise ValidationError for invalid hash."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            # Too short
            with pytest.raises(ValidationError):
                await client.check_hash("A" * 63)

            # Too long
            with pytest.raises(ValidationError):
                await client.check_hash("A" * 65)

            # Invalid characters
            with pytest.raises(ValidationError):
                await client.check_hash("G" * 64)


class TestCheckBatch:
    """Tests for checkBatch method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_return_results_for_all_credentials(self) -> None:
        """Should return results for all credentials."""
        hmac_key = "e" * 64
        credentials = [
            Credential(email="user1@test.com", password="pass1"),
            Credential(email="user2@test.com", password="pass2"),
        ]

        hash1 = hash_credential(credentials[0].email, credentials[0].password)

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[hmac_sha256(hash1, hmac_key)],  # Only first credential is compromised
                headers={
                    "X-Prefix": hash1[:5],
                    "X-HMAC-Key": hmac_key,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "1",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            results = await client.check_batch(credentials)

            assert len(results) == 2
            assert results[0].found is True
            assert results[0].credential.email == "user1@test.com"

    @pytest.mark.asyncio
    async def test_should_return_empty_array_for_empty_input(self) -> None:
        """Should return empty array for empty input."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            results = await client.check_batch([])

            assert results == []

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_if_any_credential_invalid(self) -> None:
        """Should raise ValidationError if any credential is invalid."""
        credentials = [
            Credential(email="valid@test.com", password="pass"),
            Credential(email="", password="pass"),  # Invalid
        ]

        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            with pytest.raises(ValidationError):
                await client.check_batch(credentials)


class TestCaching:
    """Tests for caching behavior."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_not_cache_when_disabled(self) -> None:
        """Should not cache when disabled."""
        hmac_key = "0" * 64

        route = respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": hmac_key,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "0",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            await client.check("user@test.com", "password")
            await client.check("user@test.com", "password")

            assert route.call_count == 2

    def test_should_clear_cache_when_clear_cache_called(self) -> None:
        """Should clear cache when clearCache is called."""
        client = DarkStrataCredentialCheck(
            api_key=API_KEY,
            enable_caching=True,
        )

        # The cache starts empty
        assert client.get_cache_size() == 0

        client.clear_cache()

        assert client.get_cache_size() == 0


class TestCheckOptionsClientHmac:
    """Tests for CheckOptions - clientHmac."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_include_client_hmac_in_request_url(self) -> None:
        """Should include clientHmac in request URL."""
        client_hmac = "a" * 64

        route = respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": client_hmac,
                    "X-HMAC-Source": "client",
                    "X-Total-Results": "0",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            await client.check("user@test.com", "password", CheckOptions(client_hmac=client_hmac))

            assert route.called
            assert f"clientHmac={client_hmac}" in str(route.calls[0].request.url)

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_return_hmac_source_as_client_when_using_client_hmac(self) -> None:
        """Should return hmacSource as client when using clientHmac."""
        client_hmac = "b" * 64

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": client_hmac,
                    "X-HMAC-Source": "client",
                    "X-Total-Results": "0",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check(
                "user@test.com", "password", CheckOptions(client_hmac=client_hmac)
            )

            assert result.metadata.hmac_source == "client"
            assert result.metadata.time_window is None

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_for_client_hmac_too_short(self) -> None:
        """Should raise ValidationError for clientHmac that is too short."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            with pytest.raises(ValidationError):
                await client.check(
                    "user@test.com", "password", CheckOptions(client_hmac="a" * 63)
                )

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_for_non_hex_client_hmac(self) -> None:
        """Should raise ValidationError for non-hex clientHmac."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            with pytest.raises(ValidationError):
                await client.check(
                    "user@test.com", "password", CheckOptions(client_hmac="g" * 64)
                )

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_not_cache_when_client_hmac_provided(self) -> None:
        """Should not cache when clientHmac is provided."""
        client_hmac = "c" * 64

        route = respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": client_hmac,
                    "X-HMAC-Source": "client",
                    "X-Total-Results": "0",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=True,
        ) as client:
            # Make two requests with clientHmac
            await client.check("user@test.com", "password", CheckOptions(client_hmac=client_hmac))
            await client.check("user@test.com", "password", CheckOptions(client_hmac=client_hmac))

            # Both should hit the API (no caching with custom options)
            assert route.call_count == 2


class TestCheckOptionsSince:
    """Tests for CheckOptions - since."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_include_since_parameter_when_number_provided(self) -> None:
        """Should include since parameter directly when number provided."""
        since_epoch_day = 19724  # 2024-01-01

        route = respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": "e" * 64,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "0",
                    "X-Filter-Since": str(since_epoch_day),
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            await client.check("user@test.com", "password", CheckOptions(since=since_epoch_day))

            assert route.called
            assert f"since={since_epoch_day}" in str(route.calls[0].request.url)

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_return_filter_since_in_metadata(self) -> None:
        """Should return filterSince in metadata."""
        since_epoch_day = 19724

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": "f" * 64,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "5",
                    "X-Filter-Since": str(since_epoch_day),
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check(
                "user@test.com", "password", CheckOptions(since=since_epoch_day)
            )

            assert result.metadata.filter_since == since_epoch_day

    @pytest.mark.asyncio
    async def test_should_raise_validation_error_for_negative_since_value(self) -> None:
        """Should raise ValidationError for negative since value."""
        async with DarkStrataCredentialCheck(api_key=API_KEY) as client:
            with pytest.raises(ValidationError):
                await client.check("user@test.com", "password", CheckOptions(since=-1))

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_not_cache_when_since_provided(self) -> None:
        """Should not cache when since is provided."""
        route = respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": "1" * 64,
                    "X-HMAC-Source": "server",
                    "X-Time-Window": "12345",
                    "X-Total-Results": "0",
                    "X-Filter-Since": "19724",
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=True,
        ) as client:
            # Make two requests with since
            await client.check("user@test.com", "password", CheckOptions(since=19724))
            await client.check("user@test.com", "password", CheckOptions(since=19724))

            # Both should hit the API (no caching with custom options)
            assert route.call_count == 2


class TestCheckOptionsCombined:
    """Tests for CheckOptions - combined."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_support_both_client_hmac_and_since_together(self) -> None:
        """Should support both clientHmac and since together."""
        client_hmac = "abcdef01" * 8
        since_epoch_day = 19724

        route = respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": client_hmac,
                    "X-HMAC-Source": "client",
                    "X-Total-Results": "10",
                    "X-Filter-Since": str(since_epoch_day),
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check(
                "user@test.com",
                "password",
                CheckOptions(client_hmac=client_hmac, since=since_epoch_day),
            )

            assert result.metadata.hmac_source == "client"
            assert result.metadata.filter_since == since_epoch_day

            # Verify both params in URL
            called_url = str(route.calls[0].request.url)
            assert f"clientHmac={client_hmac}" in called_url
            assert f"since={since_epoch_day}" in called_url

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_work_with_check_hash_and_options(self) -> None:
        """Should work with checkHash and options."""
        hash_value = "A" * 64
        since_epoch_day = 19724

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "AAAAA",
                    "X-HMAC-Key": "2" * 64,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "0",
                    "X-Filter-Since": str(since_epoch_day),
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            result = await client.check_hash(hash_value, CheckOptions(since=since_epoch_day))

            assert result.metadata.filter_since == since_epoch_day

    @respx.mock
    @pytest.mark.asyncio
    async def test_should_work_with_check_batch_and_options(self) -> None:
        """Should work with checkBatch and options."""
        credentials = [
            Credential(email="user1@test.com", password="pass1"),
        ]
        since_epoch_day = 19724

        respx.get(f"{BASE_URL}credential-check/query").mock(
            return_value=httpx.Response(
                200,
                json=[],
                headers={
                    "X-Prefix": "ABCDE",
                    "X-HMAC-Key": "3" * 64,
                    "X-HMAC-Source": "server",
                    "X-Total-Results": "0",
                    "X-Filter-Since": str(since_epoch_day),
                },
            )
        )

        async with DarkStrataCredentialCheck(
            api_key=API_KEY,
            base_url=BASE_URL,
            enable_caching=False,
        ) as client:
            results = await client.check_batch(credentials, CheckOptions(since=since_epoch_day))

            assert results[0].metadata.filter_since == since_epoch_day
