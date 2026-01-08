"""Tests for crypto utilities."""

import pytest

from darkstrata_credential_check.crypto import (
    extract_prefix,
    group_by_prefix,
    hash_credential,
    HashedCredential,
    hmac_sha256,
    is_hash_in_set,
    is_valid_hash,
    is_valid_prefix,
    sha256,
)


class TestSha256:
    """Tests for sha256 function."""

    def test_should_compute_sha256_hash_of_string(self) -> None:
        """Should compute SHA-256 hash of a string."""
        # Known test vector
        hash_value = sha256("hello")
        assert hash_value == "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"

    def test_should_return_uppercase_hex_string(self) -> None:
        """Should return uppercase hex string."""
        hash_value = sha256("test")
        assert len(hash_value) == 64
        assert hash_value == hash_value.upper()
        assert all(c in "0123456789ABCDEF" for c in hash_value)

    def test_should_produce_different_hashes_for_different_inputs(self) -> None:
        """Should produce different hashes for different inputs."""
        hash1 = sha256("input1")
        hash2 = sha256("input2")
        assert hash1 != hash2

    def test_should_produce_same_hash_for_same_input(self) -> None:
        """Should produce same hash for same input."""
        hash1 = sha256("consistent")
        hash2 = sha256("consistent")
        assert hash1 == hash2


class TestHashCredential:
    """Tests for hash_credential function."""

    def test_should_hash_email_password_format(self) -> None:
        """Should hash email:password format."""
        hash_value = hash_credential("user@example.com", "password123")
        # Verify it's a valid SHA-256 hash
        assert len(hash_value) == 64
        assert all(c in "0123456789ABCDEF" for c in hash_value)

    def test_should_produce_consistent_results(self) -> None:
        """Should produce consistent results."""
        hash1 = hash_credential("test@test.com", "pass")
        hash2 = hash_credential("test@test.com", "pass")
        assert hash1 == hash2

    def test_should_produce_different_hashes_for_different_credentials(self) -> None:
        """Should produce different hashes for different credentials."""
        hash1 = hash_credential("user1@test.com", "pass")
        hash2 = hash_credential("user2@test.com", "pass")
        assert hash1 != hash2

    def test_should_be_case_sensitive_for_email(self) -> None:
        """Should be case-sensitive for email."""
        hash1 = hash_credential("User@test.com", "pass")
        hash2 = hash_credential("user@test.com", "pass")
        assert hash1 != hash2

    def test_should_handle_special_characters_in_password(self) -> None:
        """Should handle special characters in password."""
        hash_value = hash_credential("user@test.com", "p@$$w0rd!#$%")
        assert len(hash_value) == 64
        assert all(c in "0123456789ABCDEF" for c in hash_value)

    def test_should_handle_unicode_characters(self) -> None:
        """Should handle unicode characters."""
        hash_value = hash_credential("user@test.com", "pароль日本語")
        assert len(hash_value) == 64
        assert all(c in "0123456789ABCDEF" for c in hash_value)


class TestHmacSha256:
    """Tests for hmac_sha256 function."""

    def test_should_compute_hmac_sha256(self) -> None:
        """Should compute HMAC-SHA256."""
        message = "test message"
        key = "a" * 64  # 32 bytes in hex
        hmac_value = hmac_sha256(message, key)
        assert len(hmac_value) == 64
        assert all(c in "0123456789ABCDEF" for c in hmac_value)

    def test_should_produce_different_results_with_different_keys(self) -> None:
        """Should produce different results with different keys."""
        message = "test"
        hmac1 = hmac_sha256(message, "a" * 64)
        hmac2 = hmac_sha256(message, "b" * 64)
        assert hmac1 != hmac2

    def test_should_produce_consistent_results(self) -> None:
        """Should produce consistent results."""
        message = "test"
        key = "0123456789abcdef" * 4
        hmac1 = hmac_sha256(message, key)
        hmac2 = hmac_sha256(message, key)
        assert hmac1 == hmac2


class TestExtractPrefix:
    """Tests for extract_prefix function."""

    def test_should_extract_first_5_characters(self) -> None:
        """Should extract first 5 characters."""
        hash_value = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        prefix = extract_prefix(hash_value)
        assert prefix == "5BAA6"

    def test_should_return_uppercase(self) -> None:
        """Should return uppercase."""
        hash_value = "abcdef1234567890"
        prefix = extract_prefix(hash_value)
        assert prefix == "ABCDE"

    def test_should_handle_already_uppercase_input(self) -> None:
        """Should handle already uppercase input."""
        hash_value = "ABCDEF1234567890"
        prefix = extract_prefix(hash_value)
        assert prefix == "ABCDE"


class TestIsValidHash:
    """Tests for is_valid_hash function."""

    def test_should_return_true_for_valid_64_char_hex_hash(self) -> None:
        """Should return true for valid 64-char hex hash."""
        hash_value = "A" * 64
        assert is_valid_hash(hash_value) is True

    def test_should_return_false_for_too_short_hash(self) -> None:
        """Should return false for too short hash."""
        hash_value = "A" * 63
        assert is_valid_hash(hash_value) is False

    def test_should_return_false_for_too_long_hash(self) -> None:
        """Should return false for too long hash."""
        hash_value = "A" * 65
        assert is_valid_hash(hash_value) is False

    def test_should_return_false_for_non_hex_characters(self) -> None:
        """Should return false for non-hex characters."""
        hash_value = "G" * 64
        assert is_valid_hash(hash_value) is False

    def test_should_accept_lowercase_hex(self) -> None:
        """Should accept lowercase hex."""
        hash_value = "a" * 64
        assert is_valid_hash(hash_value) is True

    def test_should_accept_custom_length(self) -> None:
        """Should accept custom length."""
        assert is_valid_hash("ABCD", 4) is True
        assert is_valid_hash("ABCD", 5) is False


class TestIsValidPrefix:
    """Tests for is_valid_prefix function."""

    def test_should_return_true_for_valid_5_char_hex_prefix(self) -> None:
        """Should return true for valid 5-char hex prefix."""
        assert is_valid_prefix("5BAA6") is True
        assert is_valid_prefix("ABCDE") is True
        assert is_valid_prefix("12345") is True

    def test_should_return_false_for_wrong_length(self) -> None:
        """Should return false for wrong length."""
        assert is_valid_prefix("ABCD") is False
        assert is_valid_prefix("ABCDEF") is False
        assert is_valid_prefix("") is False

    def test_should_return_false_for_non_hex_characters(self) -> None:
        """Should return false for non-hex characters."""
        assert is_valid_prefix("GHIJK") is False
        assert is_valid_prefix("ABCD!") is False

    def test_should_accept_lowercase(self) -> None:
        """Should accept lowercase."""
        assert is_valid_prefix("abcde") is True


class TestIsHashInSet:
    """Tests for is_hash_in_set function."""

    def test_should_return_true_when_hash_is_in_set(self) -> None:
        """Should return true when hash is in set."""
        hash_value = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8" + "0" * 24
        key = "a" * 64
        hmac_of_hash = hmac_sha256(hash_value, key)

        assert is_hash_in_set(hash_value, key, [hmac_of_hash]) is True

    def test_should_return_false_when_hash_is_not_in_set(self) -> None:
        """Should return false when hash is not in set."""
        hash_value = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8" + "0" * 24
        key = "a" * 64

        # Different hash's HMAC
        different_hash = "B" * 64
        hmac_of_different = hmac_sha256(different_hash, key)

        assert is_hash_in_set(hash_value, key, [hmac_of_different]) is False

    def test_should_handle_empty_set(self) -> None:
        """Should handle empty set."""
        hash_value = "A" * 64
        key = "a" * 64

        assert is_hash_in_set(hash_value, key, []) is False

    def test_should_find_hash_in_large_set(self) -> None:
        """Should find hash in large set."""
        target_hash = "A" * 64
        key = "a" * 64
        target_hmac = hmac_sha256(target_hash, key)

        # Create set with multiple hashes
        hashes = [
            hmac_sha256("B" * 64, key),
            hmac_sha256("C" * 64, key),
            target_hmac,
            hmac_sha256("D" * 64, key),
        ]

        assert is_hash_in_set(target_hash, key, hashes) is True

    def test_should_handle_invalid_hex_in_set_gracefully(self) -> None:
        """Should handle invalid hex in set gracefully."""
        hash_value = "A" * 64
        key = "a" * 64

        # Set contains invalid hex strings
        hashes = ["not-valid-hex", "ZZZZ", hmac_sha256(hash_value, key)]

        assert is_hash_in_set(hash_value, key, hashes) is True


class TestGroupByPrefix:
    """Tests for group_by_prefix function."""

    def test_should_group_credentials_by_prefix(self) -> None:
        """Should group credentials by prefix."""
        credentials = [
            HashedCredential(email="a1@test.com", password="p1", hash_value="AAAAA" + "0" * 59),
            HashedCredential(email="a2@test.com", password="p2", hash_value="AAAAA" + "1" * 59),
            HashedCredential(email="b1@test.com", password="p3", hash_value="BBBBB" + "0" * 59),
        ]

        groups = group_by_prefix(credentials)

        assert len(groups) == 2
        assert len(groups.get("AAAAA", [])) == 2
        assert len(groups.get("BBBBB", [])) == 1

    def test_should_handle_empty_array(self) -> None:
        """Should handle empty array."""
        groups = group_by_prefix([])
        assert len(groups) == 0

    def test_should_handle_single_item(self) -> None:
        """Should handle single item."""
        credentials = [
            HashedCredential(email="a@test.com", password="p", hash_value="ABCDE" + "0" * 59)
        ]
        groups = group_by_prefix(credentials)

        assert len(groups) == 1
        assert len(groups.get("ABCDE", [])) == 1

    def test_should_uppercase_prefix_for_grouping(self) -> None:
        """Should uppercase prefix for grouping."""
        credentials = [
            HashedCredential(email="a1@test.com", password="p1", hash_value="abcde" + "0" * 59),
            HashedCredential(email="a2@test.com", password="p2", hash_value="ABCDE" + "1" * 59),
        ]

        groups = group_by_prefix(credentials)

        # Both should be in same group (uppercase)
        assert len(groups) == 1
        assert len(groups.get("ABCDE", [])) == 2
