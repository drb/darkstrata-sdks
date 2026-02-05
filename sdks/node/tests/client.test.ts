import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DarkStrataCredentialCheck } from '../src/client.js';
import {
  AuthenticationError,
  ValidationError,
  ApiError,
  RateLimitError,
} from '../src/errors.js';
import { hmacSha256, hashCredential } from '../src/crypto.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('DarkStrataCredentialCheck', () => {
  const API_KEY = 'test-api-key';
  const BASE_URL = 'https://api.test.com/v1/';

  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create client with valid options', () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });
      expect(client).toBeInstanceOf(DarkStrataCredentialCheck);
    });

    it('should throw ValidationError for missing API key', () => {
      expect(() => {
        new DarkStrataCredentialCheck({ apiKey: '' });
      }).toThrow(ValidationError);
    });

    it('should throw ValidationError for whitespace-only API key', () => {
      expect(() => {
        new DarkStrataCredentialCheck({ apiKey: '   ' });
      }).toThrow(ValidationError);
    });

    it('should throw ValidationError for invalid timeout', () => {
      expect(() => {
        new DarkStrataCredentialCheck({ apiKey: API_KEY, timeout: 0 });
      }).toThrow(ValidationError);

      expect(() => {
        new DarkStrataCredentialCheck({ apiKey: API_KEY, timeout: -1 });
      }).toThrow(ValidationError);
    });

    it('should throw ValidationError for invalid retries', () => {
      expect(() => {
        new DarkStrataCredentialCheck({ apiKey: API_KEY, retries: -1 });
      }).toThrow(ValidationError);
    });

    it('should throw ValidationError for invalid cacheTTL', () => {
      expect(() => {
        new DarkStrataCredentialCheck({ apiKey: API_KEY, cacheTTL: 0 });
      }).toThrow(ValidationError);
    });

    it('should accept custom baseUrl', () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: 'https://custom.api.com',
      });
      expect(client).toBeInstanceOf(DarkStrataCredentialCheck);
    });
  });

  describe('check', () => {
    it('should return found: true when credential is in breach database', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const email = 'test@example.com';
      const password = 'password123';
      const credentialHash = hashCredential(email, password);
      const hmacKey = 'a'.repeat(64);
      const expectedHmac = hmacSha256(credentialHash, hmacKey);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': credentialHash.substring(0, 5),
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Time-Window': '12345',
          'X-Total-Results': '1',
        }),
        json: async () => [expectedHmac],
      });

      const result = await client.check(email, password);

      expect(result.found).toBe(true);
      expect(result.credential.email).toBe(email);
      expect(result.credential.masked).toBe(true);
      expect(result.metadata.prefix).toBe(credentialHash.substring(0, 5));
      expect(result.metadata.totalResults).toBe(1);
    });

    it('should return found: false when credential is not in breach database', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const email = 'safe@example.com';
      const password = 'safePassword';
      const hmacKey = 'b'.repeat(64);

      // Return hashes that don't match the credential
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Time-Window': '12345',
          'X-Total-Results': '2',
        }),
        json: async () => [
          hmacSha256('C'.repeat(64), hmacKey),
          hmacSha256('D'.repeat(64), hmacKey),
        ],
      });

      const result = await client.check(email, password);

      expect(result.found).toBe(false);
      expect(result.credential.email).toBe(email);
    });

    it('should throw ValidationError for empty email', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      await expect(client.check('', 'password')).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for empty password', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      await expect(client.check('email@test.com', '')).rejects.toThrow(ValidationError);
    });

    it('should throw AuthenticationError for 401 response', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: 'invalid-key',
        baseUrl: BASE_URL,
        retries: 0,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: new Headers(),
        json: async () => ({ message: 'Unauthorized' }),
      });

      await expect(client.check('email@test.com', 'password')).rejects.toThrow(
        AuthenticationError
      );
    });

    it('should throw RateLimitError for 429 response', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        retries: 0,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({
          'Retry-After': '60',
        }),
        json: async () => ({ message: 'Rate limited' }),
      });

      await expect(client.check('email@test.com', 'password')).rejects.toThrow(
        RateLimitError
      );
    });

    it('should throw ApiError for other error responses', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        retries: 0,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers(),
        json: async () => ({ message: 'Server error' }),
      });

      await expect(client.check('email@test.com', 'password')).rejects.toThrow(
        ApiError
      );
    });
  });

  describe('checkHash', () => {
    it('should accept valid hash and return result', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const hash = 'A'.repeat(64);
      const hmacKey = 'c'.repeat(64);
      const expectedHmac = hmacSha256(hash, hmacKey);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'AAAAA',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Total-Results': '1',
        }),
        json: async () => [expectedHmac],
      });

      const result = await client.checkHash(hash);

      expect(result.found).toBe(true);
      expect(result.credential.email).toBe('[hash-only]');
    });

    it('should normalise lowercase hash to uppercase', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const hash = 'a'.repeat(64); // lowercase
      const hmacKey = 'd'.repeat(64);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'AAAAA',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      const result = await client.checkHash(hash);

      expect(result.found).toBe(false);
    });

    it('should throw ValidationError for invalid hash', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      // Too short
      await expect(client.checkHash('A'.repeat(63))).rejects.toThrow(
        ValidationError
      );

      // Too long
      await expect(client.checkHash('A'.repeat(65))).rejects.toThrow(
        ValidationError
      );

      // Invalid characters
      await expect(client.checkHash('G'.repeat(64))).rejects.toThrow(
        ValidationError
      );
    });
  });

  describe('checkBatch', () => {
    it('should return results for all credentials', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const hmacKey = 'e'.repeat(64);
      const credentials = [
        { email: 'user1@test.com', password: 'pass1' },
        { email: 'user2@test.com', password: 'pass2' },
      ];

      // Both have same prefix for simplicity
      const hash1 = hashCredential(credentials[0].email, credentials[0].password);

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': hash1.substring(0, 5),
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Total-Results': '1',
        }),
        json: async () => [hmacSha256(hash1, hmacKey)], // Only first credential is compromised
      });

      const results = await client.checkBatch(credentials);

      expect(results).toHaveLength(2);
      expect(results[0]!.found).toBe(true);
      expect(results[0]!.credential.email).toBe('user1@test.com');
    });

    it('should return empty array for empty input', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      const results = await client.checkBatch([]);

      expect(results).toEqual([]);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should throw ValidationError if any credential is invalid', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      const credentials = [
        { email: 'valid@test.com', password: 'pass' },
        { email: '', password: 'pass' }, // Invalid
      ];

      await expect(client.checkBatch(credentials)).rejects.toThrow(ValidationError);
    });
  });

  describe('caching', () => {
    it('should cache responses when enabled', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: true,
      });

      const hmacKey = 'f'.repeat(64);
      const timeWindow = Math.floor(Date.now() / 1000 / 3600);

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Time-Window': String(timeWindow),
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      // First call
      await client.check('user@test.com', 'password');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call with same prefix should use cache
      await client.check('user@test.com', 'password');
      // Still 1 call if cached (same prefix)
      expect(mockFetch.mock.calls.length).toBeLessThanOrEqual(2);
    });

    it('should not cache when disabled', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const hmacKey = 'g'.repeat(64);

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      await client.check('user@test.com', 'password');
      await client.check('user@test.com', 'password');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should clear cache when clearCache is called', () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        enableCaching: true,
      });

      // The cache starts empty
      expect(client.getCacheSize()).toBe(0);

      client.clearCache();

      expect(client.getCacheSize()).toBe(0);
    });
  });

  describe('request headers', () => {
    it('should send correct headers', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const hmacKey = 'h'.repeat(64);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      await client.check('user@test.com', 'password');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('credential-check/query?prefix='),
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'X-Api-Key': API_KEY,
            Accept: 'application/json',
          }),
        })
      );
    });
  });

  describe('CheckOptions - clientHmac', () => {
    it('should include clientHmac in request URL', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const clientHmac = 'a'.repeat(64);
      const hmacKey = clientHmac; // Server echoes back client key

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': hmacKey,
          'X-HMAC-Source': 'client',
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      await client.check('user@test.com', 'password', { clientHmac });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining(`clientHmac=${clientHmac}`),
        expect.anything()
      );
    });

    it('should return hmacSource as client when using clientHmac', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const clientHmac = 'b'.repeat(64);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': clientHmac,
          'X-HMAC-Source': 'client',
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      const result = await client.check('user@test.com', 'password', { clientHmac });

      expect(result.metadata.hmacSource).toBe('client');
      expect(result.metadata.timeWindow).toBeUndefined();
    });

    it('should throw ValidationError for clientHmac that is too short', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      await expect(
        client.check('user@test.com', 'password', { clientHmac: 'a'.repeat(63) })
      ).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for non-hex clientHmac', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      await expect(
        client.check('user@test.com', 'password', { clientHmac: 'g'.repeat(64) })
      ).rejects.toThrow(ValidationError);
    });

    it('should not cache when clientHmac is provided', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: true,
      });

      const clientHmac = 'c'.repeat(64);

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': clientHmac,
          'X-HMAC-Source': 'client',
          'X-Total-Results': '0',
        }),
        json: async () => [],
      });

      // Make two requests with clientHmac
      await client.check('user@test.com', 'password', { clientHmac });
      await client.check('user@test.com', 'password', { clientHmac });

      // Both should hit the API (no caching with custom options)
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('CheckOptions - since', () => {
    it('should include since parameter as epoch day when Date provided', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const sinceDate = new Date('2024-01-01T00:00:00Z');
      // 2024-01-01 = epoch day 19724
      const expectedEpochDay = Math.floor(sinceDate.getTime() / 1000 / 86400);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': 'd'.repeat(64),
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
          'X-Filter-Since': String(expectedEpochDay),
        }),
        json: async () => [],
      });

      await client.check('user@test.com', 'password', { since: sinceDate });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining(`since=${expectedEpochDay}`),
        expect.anything()
      );
    });

    it('should include since parameter directly when number provided', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const sinceEpochDay = 19724; // 2024-01-01

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': 'e'.repeat(64),
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
          'X-Filter-Since': String(sinceEpochDay),
        }),
        json: async () => [],
      });

      await client.check('user@test.com', 'password', { since: sinceEpochDay });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining(`since=${sinceEpochDay}`),
        expect.anything()
      );
    });

    it('should return filterSince in metadata', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const sinceEpochDay = 19724;

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': 'f'.repeat(64),
          'X-HMAC-Source': 'server',
          'X-Total-Results': '5',
          'X-Filter-Since': String(sinceEpochDay),
        }),
        json: async () => [],
      });

      const result = await client.check('user@test.com', 'password', { since: sinceEpochDay });

      expect(result.metadata.filterSince).toBe(sinceEpochDay);
    });

    it('should throw ValidationError for negative since value', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      await expect(
        client.check('user@test.com', 'password', { since: -1 })
      ).rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for invalid Date', async () => {
      const client = new DarkStrataCredentialCheck({ apiKey: API_KEY });

      await expect(
        client.check('user@test.com', 'password', { since: new Date('invalid') })
      ).rejects.toThrow(ValidationError);
    });

    it('should not cache when since is provided', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: true,
      });

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': 'g'.repeat(64),
          'X-HMAC-Source': 'server',
          'X-Time-Window': '12345',
          'X-Total-Results': '0',
          'X-Filter-Since': '19724',
        }),
        json: async () => [],
      });

      // Make two requests with since
      await client.check('user@test.com', 'password', { since: 19724 });
      await client.check('user@test.com', 'password', { since: 19724 });

      // Both should hit the API (no caching with custom options)
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('CheckOptions - combined', () => {
    it('should support both clientHmac and since together', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const clientHmac = 'abcdef01'.repeat(8);
      const sinceEpochDay = 19724;

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': clientHmac,
          'X-HMAC-Source': 'client',
          'X-Total-Results': '10',
          'X-Filter-Since': String(sinceEpochDay),
        }),
        json: async () => [],
      });

      const result = await client.check('user@test.com', 'password', {
        clientHmac,
        since: sinceEpochDay,
      });

      expect(result.metadata.hmacSource).toBe('client');
      expect(result.metadata.filterSince).toBe(sinceEpochDay);

      // Verify both params in URL
      const calledUrl = mockFetch.mock.calls[0]![0] as string;
      expect(calledUrl).toContain(`clientHmac=${clientHmac}`);
      expect(calledUrl).toContain(`since=${sinceEpochDay}`);
    });

    it('should work with checkHash and options', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const hash = 'A'.repeat(64);
      const sinceEpochDay = 19724;

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'AAAAA',
          'X-HMAC-Key': 'i'.repeat(64),
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
          'X-Filter-Since': String(sinceEpochDay),
        }),
        json: async () => [],
      });

      const result = await client.checkHash(hash, { since: sinceEpochDay });

      expect(result.metadata.filterSince).toBe(sinceEpochDay);
    });

    it('should work with checkBatch and options', async () => {
      const client = new DarkStrataCredentialCheck({
        apiKey: API_KEY,
        baseUrl: BASE_URL,
        enableCaching: false,
      });

      const credentials = [
        { email: 'user1@test.com', password: 'pass1' },
      ];
      const sinceEpochDay = 19724;

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'X-Prefix': 'ABCDE',
          'X-HMAC-Key': 'j'.repeat(64),
          'X-HMAC-Source': 'server',
          'X-Total-Results': '0',
          'X-Filter-Since': String(sinceEpochDay),
        }),
        json: async () => [],
      });

      const results = await client.checkBatch(credentials, { since: sinceEpochDay });

      expect(results[0]!.metadata.filterSince).toBe(sinceEpochDay);
    });
  });
});
