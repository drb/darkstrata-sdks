/**
 * @darkstrata/shield - Cryptographic utilities
 *
 * All hashing uses Web Crypto API (SubtleCrypto) which is:
 * - Available in all modern browsers
 * - Secure and hardware-accelerated
 * - Async (non-blocking)
 */

/** Length of k-anonymity prefix (first N chars of hash) */
export const K_ANONYMITY_PREFIX_LENGTH = 5;

/**
 * Check if Web Crypto API is available
 * Throws if not available (requires HTTPS in browsers)
 */
function requireCrypto(): SubtleCrypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. Shield requires HTTPS.');
  }
  return crypto.subtle;
}

/**
 * Compute SHA-256 hash of a string
 *
 * @param message - String to hash
 * @returns Hex-encoded SHA-256 hash (64 characters)
 */
export async function sha256(message: string): Promise<string> {
  const subtle = requireCrypto();
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA-1 hash of a string (for k-anonymity compatibility)
 *
 * Note: SHA-1 is used for k-anonymity breach checking to maintain
 * compatibility with HIBP-style APIs. The password is never sent
 * in full - only the first 5 characters of the hash.
 *
 * @param message - String to hash
 * @returns Hex-encoded SHA-1 hash (40 characters)
 */
export async function sha1(message: string): Promise<string> {
  const subtle = requireCrypto();
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await subtle.digest('SHA-1', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute HMAC-SHA256 of a message with a key
 *
 * Used for customer-isolated user ID hashing.
 *
 * @param message - Message to sign
 * @param key - Secret key (customer salt)
 * @returns Hex-encoded HMAC-SHA256 (64 characters)
 */
export async function hmacSha256(message: string, key: string): Promise<string> {
  const subtle = requireCrypto();
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(message);

  const cryptoKey = await subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await subtle.sign('HMAC', cryptoKey, messageData);
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Normalise an email address for consistent hashing
 *
 * - Lowercase
 * - Trim whitespace
 * - Handle Gmail dot-insensitivity and plus-addressing
 *
 * @param email - Raw email address
 * @returns Normalised email address
 */
export function normaliseEmail(email: string): string {
  let normalised = email.toLowerCase().trim();

  const atIndex = normalised.indexOf('@');
  if (atIndex === -1) {
    return normalised;
  }

  const local = normalised.slice(0, atIndex);
  const domain = normalised.slice(atIndex + 1);

  // Gmail and Google Apps treat dots as insignificant
  // and support plus-addressing
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    const cleanLocal = local.split('+')[0].replace(/\./g, '');
    return `${cleanLocal}@gmail.com`;
  }

  return normalised;
}

/**
 * Generate a user ID hash from an email address
 *
 * Uses HMAC-SHA256 with customer-specific salt for:
 * - Irreversibility (can't recover email from hash)
 * - Customer isolation (same email produces different hash per customer)
 * - Consistency (same email always produces same hash for same customer)
 *
 * @param email - User's email address
 * @param salt - Customer's HMAC salt
 * @returns 64-character hex hash
 */
export async function generateUserIdHash(email: string, salt: string): Promise<string> {
  const normalised = normaliseEmail(email);
  return hmacSha256(normalised, salt);
}

/**
 * Generate a combined credential hash from email and password
 *
 * Creates SHA-256 of "email:password".
 * - Email is normalised (lowercase, trim, Gmail dot-handling)
 * - Password is NOT normalised (hashed exactly as provided)
 * - Combined with colon separator before hashing
 * - Returns uppercase hex to match credential check API format
 *
 * @param email - User's email address
 * @param password - User's password (not normalised)
 * @returns 64-character uppercase hex hash
 */
export async function generateCredentialHash(
  email: string,
  password: string
): Promise<string> {
  const normalisedEmail = normaliseEmail(email);
  const combined = `${normalisedEmail}:${password}`;
  const hash = await sha256(combined);
  return hash.toUpperCase();
}

/**
 * Simple sync hash for non-critical fingerprinting
 * (Used for hardware/browser components where async isn't ideal)
 *
 * @param message - String to hash
 * @returns 8-character hex hash
 */
export function simpleHash(message: string): string {
  let hash = 0;
  for (let i = 0; i < message.length; i++) {
    const char = message.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}
