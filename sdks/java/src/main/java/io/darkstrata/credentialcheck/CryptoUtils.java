package io.darkstrata.credentialcheck;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Cryptographic utilities for credential checking.
 */
public final class CryptoUtils {

    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9A-Fa-f]+$");
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private CryptoUtils() {
        // Utility class
    }

    /**
     * Hash a credential (email:password) using SHA-256.
     * The email is normalized (lowercased and trimmed) before hashing.
     *
     * @param email    the email address
     * @param password the password
     * @return uppercase hex-encoded SHA-256 hash
     */
    public static String hashCredential(String email, String password) {
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        return sha256(normalizedEmail + ":" + password);
    }

    /**
     * Compute SHA-256 hash of the input string.
     *
     * @param input the input string
     * @return uppercase hex-encoded SHA-256 hash
     */
    public static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Compute HMAC-SHA256 of a message with a hex-encoded key.
     *
     * @param message the message to authenticate
     * @param keyHex  the key in hex format
     * @return uppercase hex-encoded HMAC
     */
    public static String hmacSha256(String message, String keyHex) {
        try {
            byte[] keyBytes = hexToBytes(keyHex);
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("HmacSHA256 algorithm not available", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid HMAC key", e);
        }
    }

    /**
     * Extract the prefix (first 5 characters) from a hash.
     *
     * @param hash the full hash
     * @return the 5-character prefix in uppercase
     */
    public static String extractPrefix(String hash) {
        if (hash == null || hash.length() < Constants.PREFIX_LENGTH) {
            throw new IllegalArgumentException("Hash must be at least " + Constants.PREFIX_LENGTH + " characters");
        }
        return hash.substring(0, Constants.PREFIX_LENGTH).toUpperCase(Locale.ROOT);
    }

    /**
     * Validate that a string is a valid hex hash of expected length.
     *
     * @param hash           the hash to validate
     * @param expectedLength the expected length (default 64 for SHA-256)
     * @return true if valid
     */
    public static boolean isValidHash(String hash, int expectedLength) {
        if (hash == null || hash.length() != expectedLength) {
            return false;
        }
        return HEX_PATTERN.matcher(hash).matches();
    }

    /**
     * Validate that a string is a valid SHA-256 hash (64 hex characters).
     */
    public static boolean isValidHash(String hash) {
        return isValidHash(hash, 64);
    }

    /**
     * Validate that a string is a valid hash prefix (5 hex characters).
     */
    public static boolean isValidPrefix(String prefix) {
        if (prefix == null || prefix.length() != Constants.PREFIX_LENGTH) {
            return false;
        }
        return HEX_PATTERN.matcher(prefix).matches();
    }

    /**
     * Check if a hash is in a set of HMAC'd hashes using timing-safe comparison.
     *
     * @param hash       the full credential hash
     * @param hmacKey    the HMAC key in hex
     * @param hmacHashes the list of HMAC'd hashes from the API
     * @return true if the hash is found in the set
     */
    public static boolean isHashInSet(String hash, String hmacKey, List<String> hmacHashes) {
        String hmacOfHash = hmacSha256(hash.toUpperCase(Locale.ROOT), hmacKey);

        // Timing-safe comparison - always compare against all hashes
        boolean found = false;
        for (String hmacHash : hmacHashes) {
            if (timingSafeEquals(hmacOfHash, hmacHash.toUpperCase(Locale.ROOT))) {
                found = true;
                // Don't break early - continue to prevent timing attacks
            }
        }
        return found;
    }

    /**
     * Group credentials by their hash prefix.
     *
     * @param credentials list of credentials with computed hashes
     * @return map of prefix to list of credentials
     */
    public static <T> Map<String, List<T>> groupByPrefix(List<T> credentials, java.util.function.Function<T, String> hashExtractor) {
        Map<String, List<T>> groups = new HashMap<>();
        for (T credential : credentials) {
            String hash = hashExtractor.apply(credential);
            String prefix = extractPrefix(hash);
            groups.computeIfAbsent(prefix, k -> new ArrayList<>()).add(credential);
        }
        return groups;
    }

    /**
     * Convert bytes to uppercase hex string.
     */
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Convert hex string to bytes.
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Timing-safe string comparison.
     */
    private static boolean timingSafeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
