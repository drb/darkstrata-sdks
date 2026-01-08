/**
 * @darkstrata/credential-check
 *
 * Check if credentials have been exposed in data breaches using k-anonymity.
 *
 * @packageDocumentation
 */

// Main client
export { DarkStrataCredentialCheck } from './client.js';

// Types
export type {
  ClientOptions,
  Credential,
  CheckOptions,
  CheckResult,
  CheckMetadata,
} from './types.js';

// Errors
export {
  DarkStrataError,
  AuthenticationError,
  ValidationError,
  ApiError,
  TimeoutError,
  NetworkError,
  RateLimitError,
  ErrorCode,
  isDarkStrataError,
  isRetryableError,
} from './errors.js';

// Crypto utilities (for advanced users)
export {
  hashCredential,
  sha256,
  hmacSha256,
  extractPrefix,
  isValidHash,
  isValidPrefix,
} from './crypto.js';

// Constants (for advanced users)
export {
  DEFAULT_BASE_URL,
  DEFAULT_TIMEOUT,
  DEFAULT_RETRIES,
  DEFAULT_CACHE_TTL,
  PREFIX_LENGTH,
  TIME_WINDOW_SECONDS,
} from './constants.js';
