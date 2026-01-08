"""
darkstrata-credential-check

Check if credentials have been exposed in data breaches using k-anonymity.
"""

# Main client
from .client import DarkStrataCredentialCheck

# Types
from .types import (
    CheckMetadata,
    CheckOptions,
    CheckResult,
    ClientOptions,
    Credential,
    CredentialInfo,
)

# Errors
from .errors import (
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

# Crypto utilities (for advanced users)
from .crypto import (
    extract_prefix,
    hash_credential,
    hmac_sha256,
    is_valid_hash,
    is_valid_prefix,
    sha256,
)

# Constants (for advanced users)
from .constants import (
    DEFAULT_BASE_URL,
    DEFAULT_CACHE_TTL,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    PREFIX_LENGTH,
    TIME_WINDOW_SECONDS,
)

__version__ = "0.1.0"

__all__ = [
    # Main client
    "DarkStrataCredentialCheck",
    # Types
    "ClientOptions",
    "Credential",
    "CheckOptions",
    "CheckResult",
    "CheckMetadata",
    "CredentialInfo",
    # Errors
    "DarkStrataError",
    "AuthenticationError",
    "ValidationError",
    "ApiError",
    "TimeoutError",
    "NetworkError",
    "RateLimitError",
    "ErrorCode",
    "is_darkstrata_error",
    "is_retryable_error",
    # Crypto utilities
    "hash_credential",
    "sha256",
    "hmac_sha256",
    "extract_prefix",
    "is_valid_hash",
    "is_valid_prefix",
    # Constants
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_RETRIES",
    "DEFAULT_CACHE_TTL",
    "PREFIX_LENGTH",
    "TIME_WINDOW_SECONDS",
    # Version
    "__version__",
]
