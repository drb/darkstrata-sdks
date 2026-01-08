import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { PREFIX_LENGTH } from './constants.js';

/**
 * Compute SHA-256 hash of a credential pair.
 *
 * The credential is formatted as `email:password` before hashing.
 *
 * @param email - The email address or username
 * @param password - The password
 * @returns The SHA-256 hash as an uppercase hexadecimal string
 *
 * @example
 * ```typescript
 * const hash = hashCredential('user@example.com', 'password123');
 * // Returns: '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...'
 * ```
 */
export function hashCredential(email: string, password: string): string {
  const credential = `${email}:${password}`;
  return createHash('sha256').update(credential).digest('hex').toUpperCase();
}

/**
 * Compute SHA-256 hash of a string.
 *
 * @param input - The string to hash
 * @returns The SHA-256 hash as an uppercase hexadecimal string
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex').toUpperCase();
}

/**
 * Compute HMAC-SHA256 of a message with a key.
 *
 * @param message - The message to authenticate
 * @param key - The HMAC key (hex string)
 * @returns The HMAC-SHA256 as an uppercase hexadecimal string
 *
 * @example
 * ```typescript
 * const hmac = hmacSha256(hash, apiHmacKey);
 * ```
 */
export function hmacSha256(message: string, key: string): string {
  const keyBuffer = Buffer.from(key, 'hex');
  return createHmac('sha256', keyBuffer)
    .update(message)
    .digest('hex')
    .toUpperCase();
}

/**
 * Extract the k-anonymity prefix from a hash.
 *
 * @param hash - The full SHA-256 hash (64 hex characters)
 * @returns The first 5 characters (prefix) in uppercase
 *
 * @example
 * ```typescript
 * const prefix = extractPrefix('5baa61e4c9b93f3f0682250b6cf8331b...');
 * // Returns: '5BAA6'
 * ```
 */
export function extractPrefix(hash: string): string {
  return hash.substring(0, PREFIX_LENGTH).toUpperCase();
}

/**
 * Check if a hash is in a set of HMAC'd hashes.
 *
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param hash - The full hash to check
 * @param hmacKey - The HMAC key from the API response
 * @param hmacHashes - Array of HMAC'd hashes from the API
 * @returns `true` if the hash is found in the set
 *
 * @example
 * ```typescript
 * const found = isHashInSet(credentialHash, apiHmacKey, apiResponse);
 * if (found) {
 *   console.log('Credential found in breach database');
 * }
 * ```
 */
export function isHashInSet(
  hash: string,
  hmacKey: string,
  hmacHashes: string[]
): boolean {
  // Compute HMAC of the full hash
  const targetHmac = hmacSha256(hash, hmacKey);

  // Use timing-safe comparison to prevent timing attacks
  const targetBuffer = Buffer.from(targetHmac, 'hex');

  for (const hmacHash of hmacHashes) {
    try {
      const candidateBuffer = Buffer.from(hmacHash, 'hex');
      if (
        targetBuffer.length === candidateBuffer.length &&
        timingSafeEqual(targetBuffer, candidateBuffer)
      ) {
        return true;
      }
    } catch {
      // Invalid hex string, skip
      continue;
    }
  }

  return false;
}

/**
 * Validate that a string is a valid hexadecimal hash.
 *
 * @param hash - The string to validate
 * @param expectedLength - Expected length (default: 64 for SHA-256)
 * @returns `true` if the string is valid hex of the expected length
 */
export function isValidHash(hash: string, expectedLength = 64): boolean {
  if (hash.length !== expectedLength) {
    return false;
  }
  return /^[A-Fa-f0-9]+$/.test(hash);
}

/**
 * Validate that a string is a valid k-anonymity prefix.
 *
 * @param prefix - The prefix to validate
 * @returns `true` if the prefix is valid (5 hex characters)
 */
export function isValidPrefix(prefix: string): boolean {
  return prefix.length === PREFIX_LENGTH && /^[A-Fa-f0-9]+$/.test(prefix);
}

/**
 * Securely clear a string from memory by overwriting it.
 *
 * Note: Due to JavaScript string immutability, this creates a new
 * string for the variable but cannot truly clear the original from memory.
 * For maximum security, consider using Buffer for sensitive data.
 *
 * @param value - The string to clear
 * @returns An empty string
 *
 * @internal
 */
export function secureWipe(_value: string): string {
  // In JavaScript, strings are immutable, so we can only return an empty string
  // The original string will be garbage collected when no longer referenced
  // For truly sensitive operations, use Buffer which can be zeroed
  return '';
}

/**
 * Group credentials by their hash prefix for efficient batch processing.
 *
 * @param credentials - Array of credential objects with hash property
 * @returns Map of prefix to array of credentials
 *
 * @internal
 */
export function groupByPrefix<T extends { hash: string }>(
  credentials: T[]
): Map<string, T[]> {
  const groups = new Map<string, T[]>();

  for (const credential of credentials) {
    const prefix = extractPrefix(credential.hash);
    const existing = groups.get(prefix);
    if (existing) {
      existing.push(credential);
    } else {
      groups.set(prefix, [credential]);
    }
  }

  return groups;
}
