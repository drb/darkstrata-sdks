"""Tests for error classes."""

import pytest

from darkstrata_credential_check.errors import (
    ApiError,
    AuthenticationError,
    DarkStrataError,
    ErrorCode,
    NetworkError,
    RateLimitError,
    TimeoutError,
    ValidationError,
    is_darkstrata_error,
    is_retryable_error,
)


class TestDarkStrataError:
    """Tests for DarkStrataError base class."""

    def test_should_create_error_with_message_and_code(self) -> None:
        """Should create error with message and code."""
        error = DarkStrataError("Test error", ErrorCode.API_ERROR)

        assert str(error).endswith("Test error")
        assert error.code == ErrorCode.API_ERROR

    def test_should_set_retryable_to_false_by_default(self) -> None:
        """Should set retryable to false by default."""
        error = DarkStrataError("Test", ErrorCode.API_ERROR)
        assert error.retryable is False

    def test_should_accept_options(self) -> None:
        """Should accept options."""
        error = DarkStrataError(
            "Test",
            ErrorCode.API_ERROR,
            status_code=500,
            retryable=True,
        )

        assert error.status_code == 500
        assert error.retryable is True

    def test_should_accept_cause_option(self) -> None:
        """Should accept cause option."""
        cause = Exception("Original error")
        error = DarkStrataError("Wrapped", ErrorCode.API_ERROR, cause=cause)

        assert error.__cause__ == cause


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_should_have_default_message(self) -> None:
        """Should have default message."""
        error = AuthenticationError()

        assert "Invalid or missing API key" in str(error)
        assert error.code == ErrorCode.AUTHENTICATION_ERROR
        assert error.status_code == 401
        assert error.retryable is False

    def test_should_accept_custom_message(self) -> None:
        """Should accept custom message."""
        error = AuthenticationError("Custom auth error")
        assert "Custom auth error" in str(error)


class TestValidationError:
    """Tests for ValidationError."""

    def test_should_create_error_with_message(self) -> None:
        """Should create error with message."""
        error = ValidationError("Invalid input")

        assert "Invalid input" in str(error)
        assert error.code == ErrorCode.VALIDATION_ERROR
        assert error.retryable is False

    def test_should_store_field_name(self) -> None:
        """Should store field name."""
        error = ValidationError("Email is required", "email")

        assert error.field == "email"

    def test_should_have_none_field_when_not_provided(self) -> None:
        """Should have None field when not provided."""
        error = ValidationError("General error")
        assert error.field is None


class TestApiError:
    """Tests for ApiError."""

    def test_should_create_error_with_status_code(self) -> None:
        """Should create error with status code."""
        error = ApiError("Server error", 500)

        assert "Server error" in str(error)
        assert error.code == ErrorCode.API_ERROR
        assert error.status_code == 500

    def test_should_store_response_body(self) -> None:
        """Should store response body."""
        body = {"error": "Not found"}
        error = ApiError("Not found", 404, response_body=body)

        assert error.response_body == body

    def test_should_support_retryable_option(self) -> None:
        """Should support retryable option."""
        error = ApiError("Temporary error", 503, retryable=True)
        assert error.retryable is True

    def test_should_default_retryable_to_false(self) -> None:
        """Should default retryable to false."""
        error = ApiError("Error", 400)
        assert error.retryable is False


class TestTimeoutError:
    """Tests for TimeoutError."""

    def test_should_create_error_with_timeout_duration(self) -> None:
        """Should create error with timeout duration."""
        error = TimeoutError(5.0)

        assert "5" in str(error)
        assert error.code == ErrorCode.TIMEOUT_ERROR
        assert error.timeout_seconds == 5.0
        assert error.retryable is True

    def test_should_accept_cause(self) -> None:
        """Should accept cause."""
        cause = Exception("Abort")
        error = TimeoutError(3.0, cause)

        assert error.__cause__ == cause


class TestNetworkError:
    """Tests for NetworkError."""

    def test_should_create_error_with_message(self) -> None:
        """Should create error with message."""
        error = NetworkError("Connection refused")

        assert "Connection refused" in str(error)
        assert error.code == ErrorCode.NETWORK_ERROR
        assert error.retryable is True

    def test_should_accept_cause(self) -> None:
        """Should accept cause."""
        cause = Exception("ECONNREFUSED")
        error = NetworkError("Failed to connect", cause)

        assert error.__cause__ == cause


class TestRateLimitError:
    """Tests for RateLimitError."""

    def test_should_create_error_with_retry_after(self) -> None:
        """Should create error with retry after."""
        error = RateLimitError(60)

        assert "60" in str(error)
        assert error.code == ErrorCode.RATE_LIMIT_ERROR
        assert error.status_code == 429
        assert error.retry_after == 60
        assert error.retryable is True

    def test_should_handle_missing_retry_after(self) -> None:
        """Should handle missing retry after."""
        error = RateLimitError()

        assert "Rate limit exceeded" in str(error)
        assert error.retry_after is None


class TestIsDarkStrataError:
    """Tests for is_darkstrata_error function."""

    def test_should_return_true_for_darkstrata_error(self) -> None:
        """Should return true for DarkStrataError."""
        error = DarkStrataError("Test", ErrorCode.API_ERROR)
        assert is_darkstrata_error(error) is True

    def test_should_return_true_for_subclasses(self) -> None:
        """Should return true for subclasses."""
        assert is_darkstrata_error(AuthenticationError()) is True
        assert is_darkstrata_error(ValidationError("msg")) is True
        assert is_darkstrata_error(ApiError("msg", 500)) is True
        assert is_darkstrata_error(TimeoutError(1.0)) is True
        assert is_darkstrata_error(NetworkError("msg")) is True
        assert is_darkstrata_error(RateLimitError()) is True

    def test_should_return_false_for_regular_exception(self) -> None:
        """Should return false for regular Exception."""
        assert is_darkstrata_error(Exception("test")) is False

    def test_should_return_false_for_non_errors(self) -> None:
        """Should return false for non-errors."""
        assert is_darkstrata_error(None) is False
        assert is_darkstrata_error("error string") is False
        assert is_darkstrata_error({"message": "error"}) is False


class TestIsRetryableError:
    """Tests for is_retryable_error function."""

    def test_should_return_true_for_retryable_errors(self) -> None:
        """Should return true for retryable errors."""
        assert is_retryable_error(TimeoutError(1.0)) is True
        assert is_retryable_error(NetworkError("fail")) is True
        assert is_retryable_error(RateLimitError()) is True
        assert is_retryable_error(ApiError("err", 503, retryable=True)) is True

    def test_should_return_false_for_non_retryable_errors(self) -> None:
        """Should return false for non-retryable errors."""
        assert is_retryable_error(AuthenticationError()) is False
        assert is_retryable_error(ValidationError("msg")) is False
        assert is_retryable_error(ApiError("err", 400)) is False

    def test_should_return_false_for_non_darkstrata_errors(self) -> None:
        """Should return false for non-DarkStrata errors."""
        assert is_retryable_error(Exception("test")) is False
        assert is_retryable_error(None) is False


class TestErrorCodeEnum:
    """Tests for ErrorCode enum."""

    def test_should_have_all_expected_codes(self) -> None:
        """Should have all expected codes."""
        assert ErrorCode.AUTHENTICATION_ERROR.value == "AUTHENTICATION_ERROR"
        assert ErrorCode.VALIDATION_ERROR.value == "VALIDATION_ERROR"
        assert ErrorCode.API_ERROR.value == "API_ERROR"
        assert ErrorCode.TIMEOUT_ERROR.value == "TIMEOUT_ERROR"
        assert ErrorCode.NETWORK_ERROR.value == "NETWORK_ERROR"
        assert ErrorCode.RATE_LIMIT_ERROR.value == "RATE_LIMIT_ERROR"
