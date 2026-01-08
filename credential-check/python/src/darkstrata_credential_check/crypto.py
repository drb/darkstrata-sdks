"""
Cryptographic utilities for the DarkStrata credential check SDK.
"""

import hashlib
import hmac
import re
import secrets
from typing import Dict, List, TypeVar

from .constants import PREFIX_LENGTH

T = TypeVar("T")


def hash_credential(email: str, password: str) -> str:
    """
    Compute SHA-256 hash of a credential pair.

    The credential is formatted as `email:password` before hashing.

    Args:
        email: The email address or username.
        password: The password.

    Returns:
        The SHA-256 hash as an uppercase hexadecimal string.

    Example:
        >>> hash = hash_credential('user@example.com', 'password123')
        >>> print(hash)  # '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...'
    """
    credential = f"{email}:{password}"
    return hashlib.sha256(credential.encode()).hexdigest().upper()


def sha256(input_string: str) -> str:
    """
    Compute SHA-256 hash of a string.

    Args:
        input_string: The string to hash.

    Returns:
        The SHA-256 hash as an uppercase hexadecimal string.
    """
    return hashlib.sha256(input_string.encode()).hexdigest().upper()


def hmac_sha256(message: str, key: str) -> str:
    """
    Compute HMAC-SHA256 of a message with a key.

    Args:
        message: The message to authenticate.
        key: The HMAC key (hex string).

    Returns:
        The HMAC-SHA256 as an uppercase hexadecimal string.

    Example:
        >>> hmac_value = hmac_sha256(hash_value, api_hmac_key)
    """
    key_bytes = bytes.fromhex(key)
    return hmac.new(key_bytes, message.encode(), hashlib.sha256).hexdigest().upper()


def extract_prefix(hash_value: str) -> str:
    """
    Extract the k-anonymity prefix from a hash.

    Args:
        hash_value: The full SHA-256 hash (64 hex characters).

    Returns:
        The first 5 characters (prefix) in uppercase.

    Example:
        >>> prefix = extract_prefix('5baa61e4c9b93f3f0682250b6cf8331b...')
        >>> print(prefix)  # '5BAA6'
    """
    return hash_value[:PREFIX_LENGTH].upper()


def is_hash_in_set(hash_value: str, hmac_key: str, hmac_hashes: List[str]) -> bool:
    """
    Check if a hash is in a set of HMAC'd hashes.

    Uses timing-safe comparison to prevent timing attacks.

    Args:
        hash_value: The full hash to check.
        hmac_key: The HMAC key from the API response.
        hmac_hashes: Array of HMAC'd hashes from the API.

    Returns:
        True if the hash is found in the set.

    Example:
        >>> found = is_hash_in_set(credential_hash, api_hmac_key, api_response)
        >>> if found:
        ...     print('Credential found in breach database')
    """
    # Compute HMAC of the full hash
    target_hmac = hmac_sha256(hash_value, hmac_key)

    # Use timing-safe comparison to prevent timing attacks
    target_bytes = bytes.fromhex(target_hmac)

    for hmac_hash in hmac_hashes:
        try:
            candidate_bytes = bytes.fromhex(hmac_hash)
            if len(target_bytes) == len(candidate_bytes) and secrets.compare_digest(
                target_bytes, candidate_bytes
            ):
                return True
        except ValueError:
            # Invalid hex string, skip
            continue

    return False


def is_valid_hash(hash_value: str, expected_length: int = 64) -> bool:
    """
    Validate that a string is a valid hexadecimal hash.

    Args:
        hash_value: The string to validate.
        expected_length: Expected length (default: 64 for SHA-256).

    Returns:
        True if the string is valid hex of the expected length.
    """
    if len(hash_value) != expected_length:
        return False
    return bool(re.match(r"^[A-Fa-f0-9]+$", hash_value))


def is_valid_prefix(prefix: str) -> bool:
    """
    Validate that a string is a valid k-anonymity prefix.

    Args:
        prefix: The prefix to validate.

    Returns:
        True if the prefix is valid (5 hex characters).
    """
    return len(prefix) == PREFIX_LENGTH and bool(re.match(r"^[A-Fa-f0-9]+$", prefix))


def secure_wipe(_value: str) -> str:
    """
    Securely clear a string from memory by overwriting it.

    Note: Due to Python string immutability, this creates a new
    string for the variable but cannot truly clear the original from memory.
    For maximum security, consider using bytes for sensitive data.

    Args:
        value: The string to clear.

    Returns:
        An empty string.
    """
    # In Python, strings are immutable, so we can only return an empty string
    # The original string will be garbage collected when no longer referenced
    return ""


class HashedCredential:
    """A credential with its computed hash."""

    def __init__(self, email: str, password: str, hash_value: str) -> None:
        self.email = email
        self.password = password
        self.hash = hash_value


def group_by_prefix(credentials: List[HashedCredential]) -> Dict[str, List[HashedCredential]]:
    """
    Group credentials by their hash prefix for efficient batch processing.

    Args:
        credentials: List of credential objects with hash property.

    Returns:
        Dictionary mapping prefix to list of credentials.
    """
    groups: Dict[str, List[HashedCredential]] = {}

    for credential in credentials:
        prefix = extract_prefix(credential.hash)
        if prefix in groups:
            groups[prefix].append(credential)
        else:
            groups[prefix] = [credential]

    return groups
