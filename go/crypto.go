package credentialcheck

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"regexp"
	"strings"
)

var hexPattern = regexp.MustCompile(`^[a-fA-F0-9]+$`)

// HashCredential computes the SHA-256 hash of email:password
// The email is normalized (lowercased and trimmed) before hashing.
// Returns uppercase hex string to match server expectations
func HashCredential(email, password string) string {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	input := normalizedEmail + ":" + password
	return SHA256(input)
}

// SHA256 computes the SHA-256 hash of the input string
// Returns uppercase hex string to match server expectations
func SHA256(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// HMACSHA256 computes the HMAC-SHA256 of the message using the hex-encoded key
// Returns uppercase hex string to match server expectations
func HMACSHA256(message, hexKey string) (string, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", NewValidationError("hexKey", "invalid hex key")
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// ExtractPrefix returns the first PrefixLength characters of the hash (uppercase)
func ExtractPrefix(hash string) string {
	if len(hash) < PrefixLength {
		return strings.ToUpper(hash)
	}
	return strings.ToUpper(hash[:PrefixLength])
}

// IsHashInSet checks if the hash is in the set using timing-safe comparison
// This prevents timing attacks by comparing HMACs
func IsHashInSet(hash, hmacKey string, hmacHashes []string) (bool, error) {
	// Compute HMAC of the full hash
	computed, err := HMACSHA256(hash, hmacKey)
	if err != nil {
		return false, err
	}

	computedBytes, err := hex.DecodeString(computed)
	if err != nil {
		return false, err
	}

	// Compare against each hash in the set using constant-time comparison
	for _, h := range hmacHashes {
		hBytes, err := hex.DecodeString(h)
		if err != nil {
			continue // Skip invalid hashes
		}
		if subtle.ConstantTimeCompare(computedBytes, hBytes) == 1 {
			return true, nil
		}
	}

	return false, nil
}

// IsValidHash checks if the string is a valid hex hash of the expected length
// If expectedLength is 0, defaults to 64 (SHA-256)
func IsValidHash(hash string, expectedLength int) bool {
	if expectedLength == 0 {
		expectedLength = 64
	}
	if len(hash) != expectedLength {
		return false
	}
	return hexPattern.MatchString(hash)
}

// IsValidPrefix checks if the string is a valid k-anonymity prefix
func IsValidPrefix(prefix string) bool {
	if len(prefix) != PrefixLength {
		return false
	}
	return hexPattern.MatchString(prefix)
}

// GroupByPrefix groups credentials by their hash prefix for efficient batch processing
func GroupByPrefix[T any](items []T, getHash func(T) string) map[string][]T {
	groups := make(map[string][]T)
	for _, item := range items {
		hash := getHash(item)
		prefix := ExtractPrefix(hash)
		groups[prefix] = append(groups[prefix], item)
	}
	return groups
}

// SecureWipe attempts to clear sensitive data from memory
// Note: Go's garbage collector may still have copies, but this helps
func SecureWipe(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}
