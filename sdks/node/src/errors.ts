/**
 * Error codes for DarkStrata SDK errors.
 */
export enum ErrorCode {
  /** Invalid or missing API key */
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  /** Invalid input parameters */
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  /** API request failed */
  API_ERROR = 'API_ERROR',
  /** Request timed out */
  TIMEOUT_ERROR = 'TIMEOUT_ERROR',
  /** Network error */
  NETWORK_ERROR = 'NETWORK_ERROR',
  /** Rate limit exceeded */
  RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR',
}

/**
 * Base error class for all DarkStrata SDK errors.
 */
export class DarkStrataError extends Error {
  /**
   * Error code for programmatic error handling.
   */
  public readonly code: ErrorCode;

  /**
   * HTTP status code (if applicable).
   */
  public readonly statusCode?: number | undefined;

  /**
   * Whether this error is retryable.
   */
  public readonly retryable: boolean;

  constructor(
    message: string,
    code: ErrorCode,
    options?: {
      statusCode?: number;
      retryable?: boolean;
      cause?: unknown;
    }
  ) {
    super(message, { cause: options?.cause });
    this.name = 'DarkStrataError';
    this.code = code;
    this.statusCode = options?.statusCode;
    this.retryable = options?.retryable ?? false;
  }
}

/**
 * Error thrown when API key authentication fails.
 */
export class AuthenticationError extends DarkStrataError {
  constructor(message = 'Invalid or missing API key') {
    super(message, ErrorCode.AUTHENTICATION_ERROR, {
      statusCode: 401,
      retryable: false,
    });
    this.name = 'AuthenticationError';
  }
}

/**
 * Error thrown when input validation fails.
 */
export class ValidationError extends DarkStrataError {
  /**
   * The field that failed validation.
   */
  public readonly field?: string | undefined;

  constructor(message: string, field?: string) {
    super(message, ErrorCode.VALIDATION_ERROR, { retryable: false });
    this.name = 'ValidationError';
    this.field = field;
  }
}

/**
 * Error thrown when an API request fails.
 */
export class ApiError extends DarkStrataError {
  /**
   * Response body from the API (if available).
   */
  public readonly responseBody?: unknown;

  constructor(
    message: string,
    statusCode: number,
    options?: {
      responseBody?: unknown;
      retryable?: boolean;
      cause?: unknown;
    }
  ) {
    super(message, ErrorCode.API_ERROR, {
      statusCode,
      retryable: options?.retryable ?? false,
      cause: options?.cause,
    });
    this.name = 'ApiError';
    this.responseBody = options?.responseBody;
  }
}

/**
 * Error thrown when a request times out.
 */
export class TimeoutError extends DarkStrataError {
  /**
   * The timeout duration in milliseconds.
   */
  public readonly timeoutMs: number;

  constructor(timeoutMs: number, cause?: unknown) {
    super(`Request timed out after ${timeoutMs}ms`, ErrorCode.TIMEOUT_ERROR, {
      retryable: true,
      cause,
    });
    this.name = 'TimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Error thrown when a network error occurs.
 */
export class NetworkError extends DarkStrataError {
  constructor(message: string, cause?: unknown) {
    super(message, ErrorCode.NETWORK_ERROR, {
      retryable: true,
      cause,
    });
    this.name = 'NetworkError';
  }
}

/**
 * Error thrown when rate limit is exceeded.
 */
export class RateLimitError extends DarkStrataError {
  /**
   * Seconds until rate limit resets (if available).
   */
  public readonly retryAfter?: number | undefined;

  constructor(retryAfter?: number) {
    const message = retryAfter
      ? `Rate limit exceeded. Retry after ${retryAfter} seconds.`
      : 'Rate limit exceeded.';
    super(message, ErrorCode.RATE_LIMIT_ERROR, {
      statusCode: 429,
      retryable: true,
    });
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Type guard to check if an error is a DarkStrata SDK error.
 */
export function isDarkStrataError(error: unknown): error is DarkStrataError {
  return error instanceof DarkStrataError;
}

/**
 * Type guard to check if an error is retryable.
 */
export function isRetryableError(error: unknown): boolean {
  if (isDarkStrataError(error)) {
    return error.retryable;
  }
  return false;
}
