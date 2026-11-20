/**
 * The one HTTP call this action makes: POST /v1/secrets.
 *
 * Why this is not `cli/src/api.js` vendored verbatim, when `vendor/crypto.js`
 * and `vendor/link.js` are: the CLI hard-codes its own User-Agent prefix, and
 * the whole point of a second distribution surface is being able to tell its
 * traffic apart from the first one's in the access log. A copy with one
 * string changed is a copy that drifts quietly, so the drift is caught the
 * other way round instead — `work/ops/tests/test_gh_action.py` builds a create
 * body with this client and with the CLI's, and fails if the two disagree on
 * any field but the User-Agent. The envelope format itself stays byte-shared.
 *
 * What this module is allowed to send matters as much as what it does send: a
 * ciphertext envelope and non-sensitive metadata, and nothing else. No
 * plaintext, no key, no repository name, no workflow name, no run id, no
 * telemetry. `test/api.test.js` asserts the body field by field rather than
 * trusting this comment.
 */

const USER_AGENT_PREFIX = 'easytopaste-action';

/** An error the API itself reported, carrying its machine-readable code. */
export class ApiError extends Error {
  constructor(message, info = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = info.code ?? 'unknown';
    this.status = info.status ?? 0;
    this.requestId = info.requestId ?? null;
    this.retryAfter = info.retryAfter ?? null;
  }
}

/** The request never reached the API, or the API never answered. */
export class NetworkError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = 'NetworkError';
    this.code = 'network';
  }
}

export class ApiClient {
  /**
   * @param {{baseUrl: string, version?: string, timeoutMs?: number, fetchImpl?: typeof fetch}} opts
   */
  constructor({ baseUrl, version = '0.0.0', timeoutMs = 20_000, fetchImpl, token = '' } = {}) {
    this.baseUrl = String(baseUrl).replace(/\/+$/, '');
    this.version = version;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
    this.token = token;
  }

  /**
   * POST /v1/secrets — store one inline ciphertext envelope.
   *
   * @param {{ciphertextB64: string, sizeBytes: number, oneTime: boolean, expiresInDays: number}} args
   * @returns {Promise<{locator: string, expiresAt?: string}>}
   */
  async createSecret({ ciphertextB64, sizeBytes, oneTime, expiresInDays }) {
    const body = {
      type: 'text',
      mode: 'link',
      envelopeVersion: 1,
      sizeBytes,
      oneTime,
      expiresInDays,
      requiresRecipientLogin: false,
      mimeHint: 'text/plain',
      ciphertext: ciphertextB64,
    };

    const url = `${this.baseUrl}/v1/secrets`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          'user-agent': `${USER_AGENT_PREFIX}/${this.version}`,
          // Absent, not empty, when there is no token: an `Authorization:
          // Bearer ` header with nothing after it is a malformed credential,
          // and an API is entitled to answer 401 to it rather than treat the
          // caller as anonymous.
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (cause) {
      if (cause?.name === 'AbortError') {
        throw new NetworkError(`POST ${url} timed out after ${this.timeoutMs} ms`, cause);
      }
      throw new NetworkError(`cannot reach ${this.baseUrl} — ${cause?.message ?? cause}`, cause);
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    let json = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }

    if (!response.ok) throw toApiError(response, json);
    if (!json || typeof json.locator !== 'string') {
      throw new ApiError('the API accepted the secret but returned no locator', {
        status: response.status,
      });
    }
    return json;
  }
}

/**
 * Turn an API error envelope into a message a workflow log can act on.
 * API_SPEC §1.2: `{ "error": { code, message, request_id, hint? } }`.
 */
function toApiError(response, json) {
  const err = json && typeof json === 'object' ? json.error : null;
  const code = err?.code ?? `http_${response.status}`;
  const requestId = err?.request_id ?? err?.requestId ?? null;
  const base = err?.message || `the API answered ${response.status}`;
  const hint = err?.hint ? ` ${err.hint}` : '';
  return new ApiError(`${explain(code)}${base}${hint}`, {
    code,
    status: response.status,
    requestId,
    retryAfter: response.headers?.get?.('retry-after') ?? null,
  });
}

/** What each code means for someone staring at a red workflow. */
function explain(code) {
  switch (code) {
    case 'rate_limited':
      return 'the API is rate-limiting this runner: ';
    case 'quota_exceeded':
      return 'the daily anonymous quota for this IP is spent — hosted runners share egress addresses, so a busy org can exhaust it: ';
    case 'payload_too_large':
      return 'the value is too large for an inline link: ';
    case 'validation_error':
    case 'invalid_request':
      return 'the API rejected the request body: ';
    default:
      return '';
  }
}

export { USER_AGENT_PREFIX };
