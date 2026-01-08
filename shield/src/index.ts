/**
 * @darkstrata/shield
 *
 * Browser SDK for DarkStrata Shield login risk scoring.
 *
 * Features:
 * - Device fingerprinting (canvas, WebGL, audio, fonts, hardware)
 * - Anomaly detection (headless browsers, automation, VMs, spoofing)
 * - Credential hashing (HMAC-SHA256 for user IDs, k-anonymity for passwords)
 * - Risk scoring integration with Shield API
 *
 * @packageDocumentation
 */

// Main client
export {
  DarkStrataShield,
  init,
  getInstance,
  score,
  getFingerprint,
  getFingerprintId,
  hashCredentials,
} from './client.js';

// Types
export type {
  ShieldConfig,
  DeviceFingerprint,
  FingerprintComponents,
  FingerprintSignals,
  FingerprintAnomalies,
  ScoreOptions,
  ScoreResult,
  SignalScore,
} from './types.js';

// Constants (also usable as types)
export {
  RiskLevel,
  RecommendedAction,
  FingerprintStatus,
  ErrorCode,
} from './types.js';

// Errors
export {
  ShieldError,
  NetworkError,
  TimeoutError,
  ApiError,
  ValidationError,
  FingerprintError,
  isShieldError,
  isRetryableError,
} from './errors.js';

// Crypto utilities (for advanced users)
export {
  sha256,
  hmacSha256,
  normaliseEmail,
  generateCredentialHash,
} from './crypto.js';

// Fingerprint utilities (for advanced users)
export { collectFingerprint } from './fingerprint.js';
