import { describe, it, expect } from 'vitest';
import {
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
} from '../src/errors.js';

describe('error classes', () => {
  describe('DarkStrataError', () => {
    it('should create error with message and code', () => {
      const error = new DarkStrataError(
        'Test error',
        ErrorCode.API_ERROR
      );

      expect(error.message).toBe('Test error');
      expect(error.code).toBe(ErrorCode.API_ERROR);
      expect(error.name).toBe('DarkStrataError');
    });

    it('should set retryable to false by default', () => {
      const error = new DarkStrataError('Test', ErrorCode.API_ERROR);
      expect(error.retryable).toBe(false);
    });

    it('should accept options', () => {
      const error = new DarkStrataError('Test', ErrorCode.API_ERROR, {
        statusCode: 500,
        retryable: true,
      });

      expect(error.statusCode).toBe(500);
      expect(error.retryable).toBe(true);
    });

    it('should accept cause option', () => {
      const cause = new Error('Original error');
      const error = new DarkStrataError('Wrapped', ErrorCode.API_ERROR, {
        cause,
      });

      expect(error.cause).toBe(cause);
    });
  });

  describe('AuthenticationError', () => {
    it('should have default message', () => {
      const error = new AuthenticationError();

      expect(error.message).toBe('Invalid or missing API key');
      expect(error.code).toBe(ErrorCode.AUTHENTICATION_ERROR);
      expect(error.name).toBe('AuthenticationError');
      expect(error.statusCode).toBe(401);
      expect(error.retryable).toBe(false);
    });

    it('should accept custom message', () => {
      const error = new AuthenticationError('Custom auth error');
      expect(error.message).toBe('Custom auth error');
    });
  });

  describe('ValidationError', () => {
    it('should create error with message', () => {
      const error = new ValidationError('Invalid input');

      expect(error.message).toBe('Invalid input');
      expect(error.code).toBe(ErrorCode.VALIDATION_ERROR);
      expect(error.name).toBe('ValidationError');
      expect(error.retryable).toBe(false);
    });

    it('should store field name', () => {
      const error = new ValidationError('Email is required', 'email');

      expect(error.field).toBe('email');
    });

    it('should have undefined field when not provided', () => {
      const error = new ValidationError('General error');
      expect(error.field).toBeUndefined();
    });
  });

  describe('ApiError', () => {
    it('should create error with status code', () => {
      const error = new ApiError('Server error', 500);

      expect(error.message).toBe('Server error');
      expect(error.code).toBe(ErrorCode.API_ERROR);
      expect(error.name).toBe('ApiError');
      expect(error.statusCode).toBe(500);
    });

    it('should store response body', () => {
      const body = { error: 'Not found' };
      const error = new ApiError('Not found', 404, { responseBody: body });

      expect(error.responseBody).toEqual(body);
    });

    it('should support retryable option', () => {
      const error = new ApiError('Temporary error', 503, { retryable: true });
      expect(error.retryable).toBe(true);
    });

    it('should default retryable to false', () => {
      const error = new ApiError('Error', 400);
      expect(error.retryable).toBe(false);
    });
  });

  describe('TimeoutError', () => {
    it('should create error with timeout duration', () => {
      const error = new TimeoutError(5000);

      expect(error.message).toBe('Request timed out after 5000ms');
      expect(error.code).toBe(ErrorCode.TIMEOUT_ERROR);
      expect(error.name).toBe('TimeoutError');
      expect(error.timeoutMs).toBe(5000);
      expect(error.retryable).toBe(true);
    });

    it('should accept cause', () => {
      const cause = new Error('Abort');
      const error = new TimeoutError(3000, cause);

      expect(error.cause).toBe(cause);
    });
  });

  describe('NetworkError', () => {
    it('should create error with message', () => {
      const error = new NetworkError('Connection refused');

      expect(error.message).toBe('Connection refused');
      expect(error.code).toBe(ErrorCode.NETWORK_ERROR);
      expect(error.name).toBe('NetworkError');
      expect(error.retryable).toBe(true);
    });

    it('should accept cause', () => {
      const cause = new Error('ECONNREFUSED');
      const error = new NetworkError('Failed to connect', cause);

      expect(error.cause).toBe(cause);
    });
  });

  describe('RateLimitError', () => {
    it('should create error with retry after', () => {
      const error = new RateLimitError(60);

      expect(error.message).toBe('Rate limit exceeded. Retry after 60 seconds.');
      expect(error.code).toBe(ErrorCode.RATE_LIMIT_ERROR);
      expect(error.name).toBe('RateLimitError');
      expect(error.statusCode).toBe(429);
      expect(error.retryAfter).toBe(60);
      expect(error.retryable).toBe(true);
    });

    it('should handle missing retry after', () => {
      const error = new RateLimitError();

      expect(error.message).toBe('Rate limit exceeded.');
      expect(error.retryAfter).toBeUndefined();
    });
  });

  describe('isDarkStrataError', () => {
    it('should return true for DarkStrataError', () => {
      const error = new DarkStrataError('Test', ErrorCode.API_ERROR);
      expect(isDarkStrataError(error)).toBe(true);
    });

    it('should return true for subclasses', () => {
      expect(isDarkStrataError(new AuthenticationError())).toBe(true);
      expect(isDarkStrataError(new ValidationError('msg'))).toBe(true);
      expect(isDarkStrataError(new ApiError('msg', 500))).toBe(true);
      expect(isDarkStrataError(new TimeoutError(1000))).toBe(true);
      expect(isDarkStrataError(new NetworkError('msg'))).toBe(true);
      expect(isDarkStrataError(new RateLimitError())).toBe(true);
    });

    it('should return false for regular Error', () => {
      expect(isDarkStrataError(new Error('test'))).toBe(false);
    });

    it('should return false for non-errors', () => {
      expect(isDarkStrataError(null)).toBe(false);
      expect(isDarkStrataError(undefined)).toBe(false);
      expect(isDarkStrataError('error string')).toBe(false);
      expect(isDarkStrataError({ message: 'error' })).toBe(false);
    });
  });

  describe('isRetryableError', () => {
    it('should return true for retryable errors', () => {
      expect(isRetryableError(new TimeoutError(1000))).toBe(true);
      expect(isRetryableError(new NetworkError('fail'))).toBe(true);
      expect(isRetryableError(new RateLimitError())).toBe(true);
      expect(isRetryableError(new ApiError('err', 503, { retryable: true }))).toBe(true);
    });

    it('should return false for non-retryable errors', () => {
      expect(isRetryableError(new AuthenticationError())).toBe(false);
      expect(isRetryableError(new ValidationError('msg'))).toBe(false);
      expect(isRetryableError(new ApiError('err', 400))).toBe(false);
    });

    it('should return false for non-DarkStrata errors', () => {
      expect(isRetryableError(new Error('test'))).toBe(false);
      expect(isRetryableError(null)).toBe(false);
    });
  });

  describe('ErrorCode enum', () => {
    it('should have all expected codes', () => {
      expect(ErrorCode.AUTHENTICATION_ERROR).toBe('AUTHENTICATION_ERROR');
      expect(ErrorCode.VALIDATION_ERROR).toBe('VALIDATION_ERROR');
      expect(ErrorCode.API_ERROR).toBe('API_ERROR');
      expect(ErrorCode.TIMEOUT_ERROR).toBe('TIMEOUT_ERROR');
      expect(ErrorCode.NETWORK_ERROR).toBe('NETWORK_ERROR');
      expect(ErrorCode.RATE_LIMIT_ERROR).toBe('RATE_LIMIT_ERROR');
    });
  });
});
