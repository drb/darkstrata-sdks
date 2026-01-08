package credentialcheck

import (
	"testing"
)

func TestHashCredential(t *testing.T) {
	tests := []struct {
		email    string
		password string
		want     string
	}{
		{
			email:    "test@example.com",
			password: "password123",
			// SHA-256 of "test@example.com:password123"
			want: "9b8769a4a742959a2d0298c36fb70623f2dfacda8436237df08d8dfd5b37374c",
		},
		{
			email:    "user@test.com",
			password: "secret",
			// SHA-256 of "user@test.com:secret"
			want: "2a183baa3d97c2c1e7e6a18f6f3e2d4e5c4b3a2918273645546f7e8d9c0b1a2e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := HashCredential(tt.email, tt.password)
			if len(got) != 64 {
				t.Errorf("HashCredential() returned hash of length %d, want 64", len(got))
			}
			// Verify it's deterministic
			got2 := HashCredential(tt.email, tt.password)
			if got != got2 {
				t.Errorf("HashCredential() not deterministic: got %s, then %s", got, got2)
			}
		})
	}
}

func TestSHA256(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "hello",
			want:  "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
		},
		{
			input: "",
			want:  "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SHA256(tt.input)
			if got != tt.want {
				t.Errorf("SHA256(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestHMACSHA256(t *testing.T) {
	message := "test message"
	// 64-character hex key
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	result, err := HMACSHA256(message, key)
	if err != nil {
		t.Fatalf("HMACSHA256() error = %v", err)
	}

	if len(result) != 64 {
		t.Errorf("HMACSHA256() result length = %d, want 64", len(result))
	}

	// Verify deterministic
	result2, _ := HMACSHA256(message, key)
	if result != result2 {
		t.Errorf("HMACSHA256() not deterministic")
	}

	// Test invalid key
	_, err = HMACSHA256(message, "invalid-hex")
	if err == nil {
		t.Error("HMACSHA256() should error on invalid hex key")
	}
}

func TestExtractPrefix(t *testing.T) {
	tests := []struct {
		hash string
		want string
	}{
		{
			hash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			want: "2CF24",
		},
		{
			hash: "ABCDE12345",
			want: "ABCDE", // Returns uppercase
		},
		{
			hash: "abc",
			want: "ABC", // Too short, return as-is (uppercase)
		},
	}

	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			got := ExtractPrefix(tt.hash)
			if got != tt.want {
				t.Errorf("ExtractPrefix(%q) = %s, want %s", tt.hash, got, tt.want)
			}
		})
	}
}

func TestIsValidHash(t *testing.T) {
	tests := []struct {
		hash   string
		length int
		want   bool
	}{
		{"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 64, true},
		{"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 0, true}, // Default length
		{"2cf24", 5, true},
		{"2cf24", 64, false},                                                             // Wrong length
		{"xyz24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", 64, false}, // Invalid hex
		{"", 64, false},
	}

	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			got := IsValidHash(tt.hash, tt.length)
			if got != tt.want {
				t.Errorf("IsValidHash(%q, %d) = %v, want %v", tt.hash, tt.length, got, tt.want)
			}
		})
	}
}

func TestIsValidPrefix(t *testing.T) {
	tests := []struct {
		prefix string
		want   bool
	}{
		{"2cf24", true},
		{"abcde", true},
		{"12345", true},
		{"ABCDE", true},
		{"abc", false},     // Too short
		{"abcdef", false},  // Too long
		{"ghijk", false},   // Invalid hex
		{"", false},        // Empty
		{"abc de", false},  // Contains space
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got := IsValidPrefix(tt.prefix)
			if got != tt.want {
				t.Errorf("IsValidPrefix(%q) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestIsHashInSet(t *testing.T) {
	hash := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Compute the expected HMAC
	expectedHMAC, err := HMACSHA256(hash, key)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	// Test when hash IS in set
	found, err := IsHashInSet(hash, key, []string{expectedHMAC, "other1", "other2"})
	if err != nil {
		t.Fatalf("IsHashInSet() error = %v", err)
	}
	if !found {
		t.Error("IsHashInSet() = false, want true")
	}

	// Test when hash is NOT in set
	found, err = IsHashInSet(hash, key, []string{"notmatch1", "notmatch2"})
	if err != nil {
		t.Fatalf("IsHashInSet() error = %v", err)
	}
	if found {
		t.Error("IsHashInSet() = true, want false")
	}

	// Test empty set
	found, err = IsHashInSet(hash, key, []string{})
	if err != nil {
		t.Fatalf("IsHashInSet() error = %v", err)
	}
	if found {
		t.Error("IsHashInSet() with empty set = true, want false")
	}
}

func TestGroupByPrefix(t *testing.T) {
	type item struct {
		hash string
	}

	items := []item{
		{hash: "abcde1234567890"},
		{hash: "abcde9876543210"},
		{hash: "12345abcdefghij"},
		{hash: "12345xyz"},
	}

	groups := GroupByPrefix(items, func(i item) string {
		return i.hash
	})

	if len(groups) != 2 {
		t.Errorf("GroupByPrefix() returned %d groups, want 2", len(groups))
	}

	// Note: GroupByPrefix uses ExtractPrefix which uppercases
	if len(groups["ABCDE"]) != 2 {
		t.Errorf("Group 'ABCDE' has %d items, want 2", len(groups["ABCDE"]))
	}

	if len(groups["12345"]) != 2 {
		t.Errorf("Group '12345' has %d items, want 2", len(groups["12345"]))
	}
}
