/**
 * @darkstrata/shield - Type definitions
 */

/**
 * SDK configuration options
 */
export interface ShieldConfig {
  /** Shield API key (shld_live_xxx or shld_test_xxx) */
  apiKey: string;
  /** Customer HMAC salt for user ID hashing */
  salt: string;
  /** Base URL for Shield API (default: https://api.darkstrata.io) */
  baseUrl?: string;
  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

/**
 * Fingerprint component hashes
 */
export interface FingerprintComponents {
  canvas: string;
  webgl: string;
  audio: string;
  fonts: string;
  hardware: string;
  browser: string;
}

/**
 * Raw browser signals for server-side anomaly analysis
 */
export interface FingerprintSignals {
  screenResolution: [number, number];
  colourDepth: number;
  timezone: string;
  timezoneOffset: number;
  language: string;
  languages: string[];
  platform: string;
  cpuCores: number;
  deviceMemory: number | null;
  touchSupport: boolean;
  maxTouchPoints: number;
  webglVendor: string;
  webglRenderer: string;
  hardwareConcurrency: number;
  userAgent: string;
}

/**
 * Client-detected anomalies
 */
export interface FingerprintAnomalies {
  headlessDetected: boolean;
  automationDetected: boolean;
  vmDetected: boolean;
  spoofingDetected: boolean;
}

/**
 * Complete device fingerprint
 */
export interface DeviceFingerprint {
  /** SHA-256 hash of all components */
  fingerprintId: string;
  /** Stability confidence 0.0-1.0 */
  confidence: number;
  /** Unix timestamp */
  generatedAt: number;
  /** Generation time in milliseconds */
  generationTimeMs: number;
  /** Component hashes for partial matching */
  components: FingerprintComponents;
  /** Raw signals for anomaly detection */
  signals: FingerprintSignals;
  /** Client-detected anomalies */
  anomalies: FingerprintAnomalies;
}

/**
 * Login scoring request (internal, after hashing)
 */
export interface ScoreRequestPayload {
  /** Combined credential hash (HMAC-SHA256 of normalised_email:password) */
  credentialHash: string;
  ipAddress?: string;
  fingerprintId: string;
  fingerprintComponents: FingerprintComponents;
  fingerprintSignals: FingerprintSignals;
  fingerprintAnomalies: FingerprintAnomalies;
  loginSuccess?: boolean;
}

/**
 * User-facing score request options
 *
 * You can provide either raw values (email + password) which will be hashed automatically,
 * or a pre-hashed credentialHash if you prefer to hash on your backend.
 *
 * The credential hash is SHA-256 of "normalised_email:password" (uppercase hex).
 *
 * @example Raw values (SDK hashes automatically)
 * ```typescript
 * await shield.score({ email: 'user@example.com', password: 'secret' });
 * ```
 *
 * @example Pre-hashed value (you hash on your backend)
 * ```typescript
 * const credentialHash = await shield.hashCredentials('user@example.com', 'secret');
 * await shield.score({ credentialHash });
 * ```
 */
export interface ScoreOptions {
  /** User email (will be combined with password and hashed). Required if not providing credentialHash. */
  email?: string;
  /** User password (will be combined with email and hashed). Required if not providing credentialHash. */
  password?: string;
  /** Pre-computed credential hash (64-char hex from hashCredentials). Provide this OR email+password. */
  credentialHash?: string;
  /** Whether this is a successful login (default: true) */
  loginSuccess?: boolean;
}

/**
 * Risk level constants
 */
export const RiskLevel = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
  SEVERE: 'SEVERE',
} as const;

export type RiskLevel = (typeof RiskLevel)[keyof typeof RiskLevel];

/**
 * Recommended action constants
 */
export const RecommendedAction = {
  ALLOW: 'ALLOW',
  FLAG_FOR_REVIEW: 'FLAG_FOR_REVIEW',
  REQUIRE_CAPTCHA: 'REQUIRE_CAPTCHA',
  REQUIRE_MFA: 'REQUIRE_MFA',
  DELAY_RESPONSE: 'DELAY_RESPONSE',
  BLOCK: 'BLOCK',
} as const;

export type RecommendedAction = (typeof RecommendedAction)[keyof typeof RecommendedAction];

/**
 * Fingerprint component status constants
 */
export const FingerprintStatus = {
  UNSUPPORTED: 'unsupported',
  ERROR: 'error',
} as const;

export type FingerprintStatus = (typeof FingerprintStatus)[keyof typeof FingerprintStatus];

/**
 * Individual signal score
 */
export interface SignalScore {
  name: string;
  score: number;
  weight: number;
  details: Record<string, unknown>;
}

/**
 * Score response from Shield API
 */
export interface ScoreResult {
  /** Risk score 0.0 (safe) to 1.0 (dangerous) */
  riskScore: number;
  /** Risk level classification */
  riskLevel: RiskLevel;
  /** Recommended action to take */
  recommendedAction: RecommendedAction;
  /** Individual signal scores */
  signals: SignalScore[];
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Request ID for debugging */
  requestId?: string;
}

/**
 * Error codes
 */
export enum ErrorCode {
  INVALID_API_KEY = 'INVALID_API_KEY',
  INVALID_SALT = 'INVALID_SALT',
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT',
  API_ERROR = 'API_ERROR',
  FINGERPRINT_ERROR = 'FINGERPRINT_ERROR',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
}
