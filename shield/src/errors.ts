/**
 * @darkstrata/shield - Error classes
 */

import { ErrorCode } from './types.js';

/**
 * Base error class for Shield SDK
 */
export class ShieldError extends Error {
  readonly code: ErrorCode;
  readonly cause?: Error;

  constructor(code: ErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = 'ShieldError';
    this.code = code;
    this.cause = cause;
    Object.setPrototypeOf(this, ShieldError.prototype);
  }
}

/**
 * Network error (fetch failed)
 */
export class NetworkError extends ShieldError {
  constructor(message: string, cause?: Error) {
    super(ErrorCode.NETWORK_ERROR, message, cause);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Timeout error
 */
export class TimeoutError extends ShieldError {
  constructor(message: string) {
    super(ErrorCode.TIMEOUT, message);
    this.name = 'TimeoutError';
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

/**
 * API error (non-2xx response)
 */
export class ApiError extends ShieldError {
  readonly statusCode: number;
  readonly response?: unknown;

  constructor(message: string, statusCode: number, response?: unknown) {
    super(ErrorCode.API_ERROR, message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.response = response;
    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

/**
 * Validation error (invalid input)
 */
export class ValidationError extends ShieldError {
  readonly field?: string;

  constructor(message: string, field?: string) {
    super(ErrorCode.VALIDATION_ERROR, message);
    this.name = 'ValidationError';
    this.field = field;
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Fingerprint error
 */
export class FingerprintError extends ShieldError {
  constructor(message: string, cause?: Error) {
    super(ErrorCode.FINGERPRINT_ERROR, message, cause);
    this.name = 'FingerprintError';
    Object.setPrototypeOf(this, FingerprintError.prototype);
  }
}

/**
 * Type guard for ShieldError
 */
export function isShieldError(error: unknown): error is ShieldError {
  return error instanceof ShieldError;
}

/**
 * Check if error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof NetworkError) return true;
  if (error instanceof TimeoutError) return true;
  if (error instanceof ApiError) {
    // Retry on 5xx server errors and 429 rate limit
    return error.statusCode >= 500 || error.statusCode === 429;
  }
  return false;
}
