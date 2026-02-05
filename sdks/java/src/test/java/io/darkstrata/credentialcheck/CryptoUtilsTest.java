package io.darkstrata.credentialcheck;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CryptoUtils Tests")
class CryptoUtilsTest {

    @Test
    @DisplayName("sha256 produces correct hash")
    void sha256ProducesCorrectHash() {
        // SHA256 of empty string
        assertEquals(
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                CryptoUtils.sha256("")
        );

        // SHA256 of "hello"
        assertEquals(
                "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
                CryptoUtils.sha256("hello")
        );
    }

    @Test
    @DisplayName("hashCredential produces correct hash")
    void hashCredentialProducesCorrectHash() {
        String hash = CryptoUtils.hashCredential("test@example.com", "password123");

        assertNotNull(hash);
        assertEquals(64, hash.length());
        assertTrue(hash.matches("^[0-9A-F]+$"));
    }

    @Test
    @DisplayName("hmacSha256 produces correct HMAC")
    void hmacSha256ProducesCorrectHmac() {
        // Test with a known key and message
        String key = "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B";
        String message = "test";

        String hmac = CryptoUtils.hmacSha256(message, key);

        assertNotNull(hmac);
        assertEquals(64, hmac.length());
        assertTrue(hmac.matches("^[0-9A-F]+$"));
    }

    @Test
    @DisplayName("extractPrefix returns first 5 characters")
    void extractPrefixReturnsFirst5Characters() {
        String hash = "ABCDE12345";
        assertEquals("ABCDE", CryptoUtils.extractPrefix(hash));
    }

    @Test
    @DisplayName("extractPrefix normalizes to uppercase")
    void extractPrefixNormalizesToUppercase() {
        String hash = "abcde12345";
        assertEquals("ABCDE", CryptoUtils.extractPrefix(hash));
    }

    @Test
    @DisplayName("extractPrefix throws on short input")
    void extractPrefixThrowsOnShortInput() {
        assertThrows(IllegalArgumentException.class, () -> CryptoUtils.extractPrefix("ABC"));
    }

    @Test
    @DisplayName("isValidHash validates 64 hex characters")
    void isValidHashValidates64HexCharacters() {
        String validHash = "A".repeat(64);
        String invalidLength = "A".repeat(63);
        String invalidChars = "G".repeat(64);

        assertTrue(CryptoUtils.isValidHash(validHash));
        assertFalse(CryptoUtils.isValidHash(invalidLength));
        assertFalse(CryptoUtils.isValidHash(invalidChars));
        assertFalse(CryptoUtils.isValidHash(null));
    }

    @Test
    @DisplayName("isValidHash accepts custom length")
    void isValidHashAcceptsCustomLength() {
        assertTrue(CryptoUtils.isValidHash("ABCD", 4));
        assertFalse(CryptoUtils.isValidHash("ABCD", 5));
    }

    @Test
    @DisplayName("isValidPrefix validates 5 hex characters")
    void isValidPrefixValidates5HexCharacters() {
        assertTrue(CryptoUtils.isValidPrefix("ABCDE"));
        assertTrue(CryptoUtils.isValidPrefix("12345"));
        assertTrue(CryptoUtils.isValidPrefix("abcde"));
        assertFalse(CryptoUtils.isValidPrefix("ABCD"));
        assertFalse(CryptoUtils.isValidPrefix("ABCDEF"));
        assertFalse(CryptoUtils.isValidPrefix("GHIJK"));
        assertFalse(CryptoUtils.isValidPrefix(null));
    }

    @Test
    @DisplayName("isHashInSet finds matching hash")
    void isHashInSetFindsMatchingHash() {
        String hash = CryptoUtils.hashCredential("test@example.com", "password123");
        String hmacKey = "A".repeat(64);

        // Create the HMAC of the hash
        String expectedHmac = CryptoUtils.hmacSha256(hash, hmacKey);

        List<String> hmacHashes = Arrays.asList(
                CryptoUtils.hmacSha256("OTHER1", hmacKey),
                expectedHmac,
                CryptoUtils.hmacSha256("OTHER2", hmacKey)
        );

        assertTrue(CryptoUtils.isHashInSet(hash, hmacKey, hmacHashes));
    }

    @Test
    @DisplayName("isHashInSet returns false for non-matching hash")
    void isHashInSetReturnsFalseForNonMatchingHash() {
        String hash = CryptoUtils.hashCredential("test@example.com", "password123");
        String hmacKey = "A".repeat(64);

        List<String> hmacHashes = Arrays.asList(
                CryptoUtils.hmacSha256("OTHER1", hmacKey),
                CryptoUtils.hmacSha256("OTHER2", hmacKey)
        );

        assertFalse(CryptoUtils.isHashInSet(hash, hmacKey, hmacHashes));
    }

    @Test
    @DisplayName("groupByPrefix groups credentials correctly")
    void groupByPrefixGroupsCredentialsCorrectly() {
        List<String> hashes = Arrays.asList(
                "ABCDE1111111111111111111111111111111111111111111111111111111111",
                "ABCDE2222222222222222222222222222222222222222222222222222222222",
                "12345AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        Map<String, List<String>> grouped = CryptoUtils.groupByPrefix(hashes, hash -> hash);

        assertEquals(2, grouped.size());
        assertEquals(2, grouped.get("ABCDE").size());
        assertEquals(1, grouped.get("12345").size());
    }
}
