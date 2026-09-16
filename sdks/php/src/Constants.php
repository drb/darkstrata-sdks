<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck;

final class Constants
{
    public const VERSION = '2.6.0';
    public const DEFAULT_BASE_URL = 'https://api.darkstrata.io/v1/';
    public const DEFAULT_TIMEOUT = 30.0;
    public const DEFAULT_RETRIES = 3;
    public const DEFAULT_CACHE_TTL = 3600;

    /** Default k-anonymity prefix length. 6 returns ~16x fewer results at the cost of a smaller anonymity set. */
    public const PREFIX_LENGTH = 5;
    public const MIN_PREFIX_LENGTH = 5;
    public const MAX_PREFIX_LENGTH = 6;

    /** Server HMAC key rotation interval in seconds. */
    public const TIME_WINDOW_SECONDS = 3600;

    public const ENDPOINT = 'credential-check/query';
    public const API_KEY_HEADER = 'X-Api-Key';

    public const HEADER_PREFIX = 'x-prefix';
    public const HEADER_HMAC_KEY = 'x-hmac-key';
    public const HEADER_HMAC_SOURCE = 'x-hmac-source';
    public const HEADER_TIME_WINDOW = 'x-time-window';
    public const HEADER_TOTAL_RESULTS = 'x-total-results';
    public const HEADER_FILTER_SINCE = 'x-filter-since';

    public const RETRY_INITIAL_DELAY = 1.0;
    public const RETRY_MAX_DELAY = 10.0;
    public const RETRY_BACKOFF_BASE = 2.0;
    public const RETRYABLE_STATUS_CODES = [408, 429, 500, 502, 503, 504];
}
