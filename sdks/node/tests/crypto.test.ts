import { describe, it, expect } from 'vitest';
import {
  hashCredential,
  sha256,
  hmacSha256,
  extractPrefix,
  isHashInSet,
  isValidHash,
  isValidPrefix,
  groupByPrefix,
} from '../src/crypto.js';

describe('crypto utilities', () => {
  describe('sha256', () => {
    it('should compute SHA-256 hash of a string', () => {
      // Known test vector
      const hash = sha256('hello');
      expect(hash).toBe(
        '2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824'
      );
    });

    it('should return uppercase hex string', () => {
      const hash = sha256('test');
      expect(hash).toMatch(/^[A-F0-9]{64}$/);
    });

    it('should produce different hashes for different inputs', () => {
      const hash1 = sha256('input1');
      const hash2 = sha256('input2');
      expect(hash1).not.toBe(hash2);
    });

    it('should produce same hash for same input', () => {
      const hash1 = sha256('consistent');
      const hash2 = sha256('consistent');
      expect(hash1).toBe(hash2);
    });
  });

  describe('hashCredential', () => {
    it('should hash email:password format', () => {
      const hash = hashCredential('user@example.com', 'password123');
      // Verify it's a valid SHA-256 hash
      expect(hash).toMatch(/^[A-F0-9]{64}$/);
    });

    it('should produce consistent results', () => {
      const hash1 = hashCredential('test@test.com', 'pass');
      const hash2 = hashCredential('test@test.com', 'pass');
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different credentials', () => {
      const hash1 = hashCredential('user1@test.com', 'pass');
      const hash2 = hashCredential('user2@test.com', 'pass');
      expect(hash1).not.toBe(hash2);
    });

    it('should normalize email to lowercase', () => {
      const hash1 = hashCredential('User@test.com', 'pass');
      const hash2 = hashCredential('user@test.com', 'pass');
      expect(hash1).toBe(hash2);
    });

    it('should handle special characters in password', () => {
      const hash = hashCredential('user@test.com', 'p@$$w0rd!#$%');
      expect(hash).toMatch(/^[A-F0-9]{64}$/);
    });

    it('should handle unicode characters', () => {
      const hash = hashCredential('user@test.com', 'пароль日本語');
      expect(hash).toMatch(/^[A-F0-9]{64}$/);
    });
  });

  describe('hmacSha256', () => {
    it('should compute HMAC-SHA256', () => {
      const message = 'test message';
      const key = 'a'.repeat(64); // 32 bytes in hex
      const hmac = hmacSha256(message, key);
      expect(hmac).toMatch(/^[A-F0-9]{64}$/);
    });

    it('should produce different results with different keys', () => {
      const message = 'test';
      const hmac1 = hmacSha256(message, 'a'.repeat(64));
      const hmac2 = hmacSha256(message, 'b'.repeat(64));
      expect(hmac1).not.toBe(hmac2);
    });

    it('should produce consistent results', () => {
      const message = 'test';
      const key = '0123456789abcdef'.repeat(4);
      const hmac1 = hmacSha256(message, key);
      const hmac2 = hmacSha256(message, key);
      expect(hmac1).toBe(hmac2);
    });
  });

  describe('extractPrefix', () => {
    it('should extract first 5 characters', () => {
      const hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
      const prefix = extractPrefix(hash);
      expect(prefix).toBe('5BAA6');
    });

    it('should return uppercase', () => {
      const hash = 'abcdef1234567890';
      const prefix = extractPrefix(hash);
      expect(prefix).toBe('ABCDE');
    });

    it('should handle already uppercase input', () => {
      const hash = 'ABCDEF1234567890';
      const prefix = extractPrefix(hash);
      expect(prefix).toBe('ABCDE');
    });
  });

  describe('isValidHash', () => {
    it('should return true for valid 64-char hex hash', () => {
      const hash = 'A'.repeat(64);
      expect(isValidHash(hash)).toBe(true);
    });

    it('should return false for too short hash', () => {
      const hash = 'A'.repeat(63);
      expect(isValidHash(hash)).toBe(false);
    });

    it('should return false for too long hash', () => {
      const hash = 'A'.repeat(65);
      expect(isValidHash(hash)).toBe(false);
    });

    it('should return false for non-hex characters', () => {
      const hash = 'G'.repeat(64);
      expect(isValidHash(hash)).toBe(false);
    });

    it('should accept lowercase hex', () => {
      const hash = 'a'.repeat(64);
      expect(isValidHash(hash)).toBe(true);
    });

    it('should accept custom length', () => {
      expect(isValidHash('ABCD', 4)).toBe(true);
      expect(isValidHash('ABCD', 5)).toBe(false);
    });
  });

  describe('isValidPrefix', () => {
    it('should return true for valid 5-char hex prefix', () => {
      expect(isValidPrefix('5BAA6')).toBe(true);
      expect(isValidPrefix('ABCDE')).toBe(true);
      expect(isValidPrefix('12345')).toBe(true);
    });

    it('should return false for wrong length', () => {
      expect(isValidPrefix('ABCD')).toBe(false);
      expect(isValidPrefix('ABCDEF')).toBe(false);
      expect(isValidPrefix('')).toBe(false);
    });

    it('should return false for non-hex characters', () => {
      expect(isValidPrefix('GHIJK')).toBe(false);
      expect(isValidPrefix('ABCD!')).toBe(false);
    });

    it('should accept lowercase', () => {
      expect(isValidPrefix('abcde')).toBe(true);
    });
  });

  describe('isHashInSet', () => {
    it('should return true when hash is in set', () => {
      const hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8' + '0'.repeat(24);
      const key = 'a'.repeat(64);
      const hmacOfHash = hmacSha256(hash, key);

      expect(isHashInSet(hash, key, [hmacOfHash])).toBe(true);
    });

    it('should return false when hash is not in set', () => {
      const hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8' + '0'.repeat(24);
      const key = 'a'.repeat(64);

      // Different hash's HMAC
      const differentHash = 'B'.repeat(64);
      const hmacOfDifferent = hmacSha256(differentHash, key);

      expect(isHashInSet(hash, key, [hmacOfDifferent])).toBe(false);
    });

    it('should handle empty set', () => {
      const hash = 'A'.repeat(64);
      const key = 'a'.repeat(64);

      expect(isHashInSet(hash, key, [])).toBe(false);
    });

    it('should find hash in large set', () => {
      const targetHash = 'A'.repeat(64);
      const key = 'a'.repeat(64);
      const targetHmac = hmacSha256(targetHash, key);

      // Create set with multiple hashes
      const hashes = [
        hmacSha256('B'.repeat(64), key),
        hmacSha256('C'.repeat(64), key),
        targetHmac,
        hmacSha256('D'.repeat(64), key),
      ];

      expect(isHashInSet(targetHash, key, hashes)).toBe(true);
    });

    it('should handle invalid hex in set gracefully', () => {
      const hash = 'A'.repeat(64);
      const key = 'a'.repeat(64);

      // Set contains invalid hex strings
      const hashes = ['not-valid-hex', 'ZZZZ', hmacSha256(hash, key)];

      expect(isHashInSet(hash, key, hashes)).toBe(true);
    });
  });

  describe('groupByPrefix', () => {
    it('should group credentials by prefix', () => {
      const credentials = [
        { hash: 'AAAAA' + '0'.repeat(59), email: 'a1@test.com' },
        { hash: 'AAAAA' + '1'.repeat(59), email: 'a2@test.com' },
        { hash: 'BBBBB' + '0'.repeat(59), email: 'b1@test.com' },
      ];

      const groups = groupByPrefix(credentials);

      expect(groups.size).toBe(2);
      expect(groups.get('AAAAA')?.length).toBe(2);
      expect(groups.get('BBBBB')?.length).toBe(1);
    });

    it('should handle empty array', () => {
      const groups = groupByPrefix([]);
      expect(groups.size).toBe(0);
    });

    it('should handle single item', () => {
      const credentials = [{ hash: 'ABCDE' + '0'.repeat(59) }];
      const groups = groupByPrefix(credentials);

      expect(groups.size).toBe(1);
      expect(groups.get('ABCDE')?.length).toBe(1);
    });

    it('should uppercase prefix for grouping', () => {
      const credentials = [
        { hash: 'abcde' + '0'.repeat(59) },
        { hash: 'ABCDE' + '1'.repeat(59) },
      ];

      const groups = groupByPrefix(credentials);

      // Both should be in same group (uppercase)
      expect(groups.size).toBe(1);
      expect(groups.get('ABCDE')?.length).toBe(2);
    });
  });
});
