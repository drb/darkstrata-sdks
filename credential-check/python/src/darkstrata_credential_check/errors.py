"""
Error classes for the DarkStrata credential check SDK.
"""

from enum import Enum
from typing import Any, Optional


class ErrorCode(str, Enum):
    """Error codes for DarkStrata SDK errors."""

    # Invalid or missing API key
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    # Invalid input parameters
    VALIDATION_ERROR = "VALIDATION_ERROR"
    # API request failed
    API_ERROR = "API_ERROR"
    # Request timed out
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    # Network error
    NETWORK_ERROR = "NETWORK_ERROR"
    # Rate limit exceeded
    RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR"


class DarkStrataError(Exception):
    """Base error class for all DarkStrata SDK errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode,
        *,
        status_code: Optional[int] = None,
        retryable: bool = False,
        cause: Optional[Exception] = None,
    ) -> None:
        """
        Create a new DarkStrata error.

        Args:
            message: Human-readable error message.
            code: Error code for programmatic error handling.
            status_code: HTTP status code (if applicable).
            retryable: Whether this error is retryable.
            cause: The underlying cause of this error.
        """
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.retryable = retryable
        self.__cause__ = cause

    def __str__(self) -> str:
        return f"{self.__class__.__name__}[{self.code.value}]: {super().__str__()}"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={super().__str__()!r}, "
            f"code={self.code!r}, "
            f"status_code={self.status_code!r}, "
            f"retryable={self.retryable!r})"
        )


class AuthenticationError(DarkStrataError):
    """Error thrown when API key authentication fails."""

    def __init__(self, message: str = "Invalid or missing API key") -> None:
        super().__init__(
            message,
            ErrorCode.AUTHENTICATION_ERROR,
            status_code=401,
            retryable=False,
        )


class ValidationError(DarkStrataError):
    """Error thrown when input validation fails."""

    def __init__(self, message: str, field: Optional[str] = None) -> None:
        """
        Create a new validation error.

        Args:
            message: Human-readable error message.
            field: The field that failed validation.
        """
        super().__init__(
            message,
            ErrorCode.VALIDATION_ERROR,
            retryable=False,
        )
        self.field = field


class ApiError(DarkStrataError):
    """Error thrown when an API request fails."""

    def __init__(
        self,
        message: str,
        status_code: int,
        *,
        response_body: Optional[Any] = None,
        retryable: bool = False,
        cause: Optional[Exception] = None,
    ) -> None:
        """
        Create a new API error.

        Args:
            message: Human-readable error message.
            status_code: HTTP status code.
            response_body: Response body from the API (if available).
            retryable: Whether this error is retryable.
            cause: The underlying cause of this error.
        """
        super().__init__(
            message,
            ErrorCode.API_ERROR,
            status_code=status_code,
            retryable=retryable,
            cause=cause,
        )
        self.response_body = response_body


class TimeoutError(DarkStrataError):
    """Error thrown when a request times out."""

    def __init__(self, timeout_seconds: float, cause: Optional[Exception] = None) -> None:
        """
        Create a new timeout error.

        Args:
            timeout_seconds: The timeout duration in seconds.
            cause: The underlying cause of this error.
        """
        super().__init__(
            f"Request timed out after {timeout_seconds}s",
            ErrorCode.TIMEOUT_ERROR,
            retryable=True,
            cause=cause,
        )
        self.timeout_seconds = timeout_seconds


class NetworkError(DarkStrataError):
    """Error thrown when a network error occurs."""

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        """
        Create a new network error.

        Args:
            message: Human-readable error message.
            cause: The underlying cause of this error.
        """
        super().__init__(
            message,
            ErrorCode.NETWORK_ERROR,
            retryable=True,
            cause=cause,
        )


class RateLimitError(DarkStrataError):
    """Error thrown when rate limit is exceeded."""

    def __init__(self, retry_after: Optional[int] = None) -> None:
        """
        Create a new rate limit error.

        Args:
            retry_after: Seconds until rate limit resets (if available).
        """
        message = (
            f"Rate limit exceeded. Retry after {retry_after} seconds."
            if retry_after
            else "Rate limit exceeded."
        )
        super().__init__(
            message,
            ErrorCode.RATE_LIMIT_ERROR,
            status_code=429,
            retryable=True,
        )
        self.retry_after = retry_after


def is_darkstrata_error(error: Any) -> bool:
    """
    Check if an error is a DarkStrata SDK error.

    Args:
        error: The error to check.

    Returns:
        True if the error is a DarkStrata SDK error.
    """
    return isinstance(error, DarkStrataError)


def is_retryable_error(error: Any) -> bool:
    """
    Check if an error is retryable.

    Args:
        error: The error to check.

    Returns:
        True if the error is retryable.
    """
    if is_darkstrata_error(error):
        return bool(error.retryable)
    return False
