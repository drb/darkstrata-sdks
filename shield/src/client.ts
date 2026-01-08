/**
 * @darkstrata/shield - Main client
 *
 * Browser SDK for DarkStrata Shield login risk scoring.
 */

import { collectFingerprint } from './fingerprint.js';
import { generateCredentialHash } from './crypto.js';
import { NetworkError, TimeoutError, ApiError, ValidationError, FingerprintError } from './errors.js';
import type {
  ShieldConfig,
  DeviceFingerprint,
  ScoreOptions,
  ScoreResult,
  ScoreRequestPayload,
} from './types.js';

const DEFAULT_BASE_URL = 'https://shield.darkstrata.io';
const DEFAULT_TIMEOUT = 10000;

/**
 * DarkStrata Shield client
 *
 * @example Basic usage: raw values (SDK hashes automatically)
 * ```typescript
 * import { DarkStrataShield, RecommendedAction } from '@darkstrata/shield';
 *
 * const shield = new DarkStrataShield({
 *   apiKey: 'shld_live_xxx',
 *   salt: 'your_customer_salt'
 * });
 *
 * const result = await shield.score({
 *   email: 'user@example.com',
 *   password: 'userpassword'
 * });
 *
 * if (result.recommendedAction === RecommendedAction.BLOCK) {
 *   // Handle high-risk login
 * }
 * ```
 *
 * @example Security-conscious: pre-hashed values (you control hashing)
 * ```typescript
 * import { DarkStrataShield, RecommendedAction } from '@darkstrata/shield';
 *
 * const shield = new DarkStrataShield({
 *   apiKey: 'shld_live_xxx',
 *   salt: 'your_customer_salt'
 * });
 *
 * // Hash credentials before passing to score()
 * const credentialHash = await shield.hashCredentials('user@example.com', 'userpassword');
 *
 * const result = await shield.score({ credentialHash });
 *
 * if (result.recommendedAction === RecommendedAction.BLOCK) {
 *   // Handle high-risk login
 * }
 * ```
 */
export class DarkStrataShield {
  private readonly config: Required<ShieldConfig>;
  private fingerprint: DeviceFingerprint | null = null;
  private fingerprintPromise: Promise<DeviceFingerprint> | null = null;

  constructor(config: ShieldConfig) {
    if (!config.apiKey) {
      throw new ValidationError('API key is required', 'apiKey');
    }
    if (!config.salt) {
      throw new ValidationError('Customer salt is required', 'salt');
    }

    this.config = {
      apiKey: config.apiKey,
      salt: config.salt,
      baseUrl: config.baseUrl ?? DEFAULT_BASE_URL,
      timeout: config.timeout ?? DEFAULT_TIMEOUT,
      debug: config.debug ?? false,
    };

    // Start fingerprint collection immediately (non-blocking)
    this.prefetchFingerprint();
  }

  /**
   * Score a login attempt
   *
   * Fingerprint collection happens automatically if not already done.
   *
   * You can provide either:
   * - Raw values (email + password) - SDK combines and hashes automatically
   * - Pre-hashed credentialHash - for security-conscious integrations
   *
   * The credential hash is HMAC-SHA256 of "normalised_email:password".
   *
   * @param options - Login details (raw or pre-hashed)
   * @returns Score result with risk level and recommended action
   *
   * @example Using raw values
   * ```typescript
   * const result = await shield.score({
   *   email: 'user@example.com',
   *   password: 'userpassword'
   * });
   * ```
   *
   * @example Using pre-hashed value
   * ```typescript
   * // Hash on your backend or earlier in the flow
   * const credentialHash = await shield.hashCredentials('user@example.com', 'userpassword');
   *
   * // Pass only the hash to score()
   * const result = await shield.score({ credentialHash });
   * ```
   */
  async score(options: ScoreOptions): Promise<ScoreResult> {
    // Validate input - must have either (email + password) or credentialHash
    if (!options.credentialHash && (!options.email || !options.password)) {
      throw new ValidationError(
        'Either credentialHash or both email and password are required',
        'credentialHash'
      );
    }

    // Warn if both raw and hashed values provided (use hashed)
    if ((options.email || options.password) && options.credentialHash) {
      this.log('Both email/password and credentialHash provided; using credentialHash');
    }

    // Get fingerprint (uses cached if available)
    const fingerprint = await this.getFingerprint();

    // Use pre-hashed credentialHash if provided, otherwise generate from email:password
    const credentialHash = options.credentialHash ??
      await generateCredentialHash(options.email!, options.password!);

    // Prepare payload
    const payload: ScoreRequestPayload = {
      credentialHash,
      fingerprintId: fingerprint.fingerprintId,
      fingerprintComponents: fingerprint.components,
      fingerprintSignals: fingerprint.signals,
      fingerprintAnomalies: fingerprint.anomalies,
      loginSuccess: options.loginSuccess ?? true,
    };

    this.log('Sending score request', { credentialHash: credentialHash.slice(0, 8) + '...' });

    // Send request
    const result = await this.request<ScoreResult>('/v1/score', payload);

    this.log('Score result', {
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      recommendedAction: result.recommendedAction,
    });

    return result;
  }

  /**
   * Get the device fingerprint
   *
   * Returns cached fingerprint if available, otherwise collects a new one.
   */
  async getFingerprint(): Promise<DeviceFingerprint> {
    if (this.fingerprint) {
      return this.fingerprint;
    }

    if (this.fingerprintPromise) {
      return this.fingerprintPromise;
    }

    return this.collectAndCacheFingerprint();
  }

  /**
   * Force re-collection of fingerprint
   *
   * Use this if you need a fresh fingerprint (e.g., after significant time has passed).
   */
  async refreshFingerprint(): Promise<DeviceFingerprint> {
    this.fingerprint = null;
    this.fingerprintPromise = null;
    return this.collectAndCacheFingerprint();
  }

  /**
   * Get the fingerprint ID only
   *
   * Useful if you need to pass the fingerprint ID to your backend.
   */
  async getFingerprintId(): Promise<string> {
    const fp = await this.getFingerprint();
    return fp.fingerprintId;
  }

  /**
   * Hash credentials (email + password) for pre-hashed scoring
   *
   * Creates SHA-256 of "normalised_email:password".
   * - Email is normalised (lowercased, trimmed, Gmail dot-handling)
   * - Password is NOT normalised (hashed exactly as provided)
   * - Returns uppercase hex to match credential check API format
   *
   * Useful for security-conscious integrations where you don't want raw
   * credentials passed to the SDK.
   *
   * @param email - User's email address
   * @param password - User's password
   * @returns 64-character uppercase hex hash
   *
   * @example
   * ```typescript
   * const credentialHash = await shield.hashCredentials('user@example.com', 'userpassword');
   * await shield.score({ credentialHash });
   * ```
   */
  async hashCredentials(email: string, password: string): Promise<string> {
    return generateCredentialHash(email, password);
  }

  /**
   * Pre-fetch fingerprint in background
   */
  private prefetchFingerprint(): void {
    // Don't await - let it run in background
    this.collectAndCacheFingerprint().catch((err) => {
      this.log('Prefetch fingerprint failed', err);
    });
  }

  /**
   * Collect fingerprint and cache it
   */
  private async collectAndCacheFingerprint(): Promise<DeviceFingerprint> {
    if (this.fingerprintPromise) {
      return this.fingerprintPromise;
    }

    this.fingerprintPromise = (async () => {
      try {
        const start = performance.now();
        const fp = await collectFingerprint();
        this.fingerprint = fp;
        this.log(`Fingerprint collected in ${(performance.now() - start).toFixed(1)}ms`, {
          id: fp.fingerprintId.slice(0, 8) + '...',
          confidence: fp.confidence,
        });
        return fp;
      } catch (err) {
        this.fingerprintPromise = null;
        throw new FingerprintError(
          'Failed to collect fingerprint',
          err instanceof Error ? err : undefined
        );
      }
    })();

    return this.fingerprintPromise;
  }

  /**
   * Make API request
   */
  private async request<T>(endpoint: string, body: unknown): Promise<T> {
    const url = `${this.config.baseUrl}${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new ApiError(
          errorBody.message || `Request failed with status ${response.status}`,
          response.status,
          errorBody
        );
      }

      return response.json();
    } catch (err) {
      clearTimeout(timeoutId);

      if (err instanceof ApiError) {
        throw err;
      }

      if (err instanceof Error) {
        if (err.name === 'AbortError') {
          throw new TimeoutError(`Request timed out after ${this.config.timeout}ms`);
        }
        throw new NetworkError(err.message, err);
      }

      throw new NetworkError('Unknown network error');
    }
  }

  /**
   * Log message (if debug enabled)
   */
  private log(message: string, data?: unknown): void {
    if (this.config.debug) {
      console.log(`[Shield] ${message}`, data ?? '');
    }
  }
}

/**
 * Create a singleton instance for simple usage
 */
let defaultInstance: DarkStrataShield | null = null;

/**
 * Initialise the default Shield instance
 *
 * @example
 * ```typescript
 * import { init, score } from '@darkstrata/shield';
 *
 * init({ apiKey: 'shld_live_xxx', salt: 'your_salt' });
 *
 * const result = await score({ email: 'user@example.com' });
 * ```
 */
export function init(config: ShieldConfig): DarkStrataShield {
  defaultInstance = new DarkStrataShield(config);
  return defaultInstance;
}

/**
 * Get the default Shield instance
 */
export function getInstance(): DarkStrataShield {
  if (!defaultInstance) {
    throw new ValidationError('Shield not initialised. Call init() first.');
  }
  return defaultInstance;
}

/**
 * Score using the default instance
 */
export async function score(options: ScoreOptions): Promise<ScoreResult> {
  return getInstance().score(options);
}

/**
 * Get fingerprint using the default instance
 */
export async function getFingerprint(): Promise<DeviceFingerprint> {
  return getInstance().getFingerprint();
}

/**
 * Get fingerprint ID using the default instance
 */
export async function getFingerprintId(): Promise<string> {
  return getInstance().getFingerprintId();
}

/**
 * Hash credentials using the default instance
 *
 * @param email - User's email address
 * @param password - User's password
 * @returns 64-character hex hash
 */
export async function hashCredentials(email: string, password: string): Promise<string> {
  return getInstance().hashCredentials(email, password);
}
