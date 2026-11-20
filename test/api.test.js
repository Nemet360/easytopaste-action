import test from 'node:test';
import assert from 'node:assert/strict';

import { ApiClient, ApiError, NetworkError, USER_AGENT_PREFIX } from '../src/api.js';

function stubFetch(responses) {
  const calls = [];
  const queue = Array.isArray(responses) ? [...responses] : [responses];
  const impl = async (url, init) => {
    calls.push({ url, init, body: init?.body ? JSON.parse(init.body) : null });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (typeof next === 'function') return next();
    return next;
  };
  impl.calls = calls;
  return impl;
}

const ok = (json, status = 201, headers = {}) => ({
  ok: status < 400,
  status,
  text: async () => JSON.stringify(json),
  headers: { get: (k) => headers[k.toLowerCase()] ?? null },
});

const created = { locator: 'MFRGGZDFMZTWQ2LK', expiresAt: '2026-11-20T21:00:00Z' };

test('the create body carries ciphertext and metadata, and nothing else', async () => {
  const fetchImpl = stubFetch(ok(created));
  const api = new ApiClient({ baseUrl: 'https://api.example.test', version: '9.9.9', fetchImpl });

  await api.createSecret({
    ciphertextB64: 'Y2lwaGVy',
    sizeBytes: 42,
    oneTime: true,
    expiresInDays: 3,
  });

  const { body } = fetchImpl.calls[0];
  assert.deepEqual(body, {
    type: 'text',
    mode: 'link',
    envelopeVersion: 1,
    sizeBytes: 42,
    oneTime: true,
    expiresInDays: 3,
    requiresRecipientLogin: false,
    mimeHint: 'text/plain',
    ciphertext: 'Y2lwaGVy',
  });
  // Named explicitly: these are the fields a "helpful" future edit would add,
  // and each one would publish something about the caller's repository.
  for (const forbidden of ['repository', 'workflow', 'runId', 'actor', 'ref', 'sha', 'key']) {
    assert.ok(!(forbidden in body), `create body must not carry ${forbidden}`);
  }
});

test('the request goes to POST /v1/secrets on the configured origin', async () => {
  const fetchImpl = stubFetch(ok(created));
  const api = new ApiClient({ baseUrl: 'https://api.example.test/', fetchImpl });
  await api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 });
  assert.equal(fetchImpl.calls[0].url, 'https://api.example.test/v1/secrets');
  assert.equal(fetchImpl.calls[0].init.method, 'POST');
});

test('the User-Agent names the action, not the CLI', async () => {
  const fetchImpl = stubFetch(ok(created));
  const api = new ApiClient({ baseUrl: 'https://api.example.test', version: '1.2.3', fetchImpl });
  await api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 });
  assert.equal(fetchImpl.calls[0].init.headers['user-agent'], `${USER_AGENT_PREFIX}/1.2.3`);
  assert.equal(USER_AGENT_PREFIX, 'easytopaste-action');
});

test('an API error envelope becomes an ApiError carrying its code', async () => {
  const fetchImpl = stubFetch(
    ok({ error: { code: 'quota_exceeded', message: 'Daily quota reached.', request_id: 'r-1' } }, 429, {
      'retry-after': '60',
    }),
  );
  const api = new ApiClient({ baseUrl: 'https://api.example.test', fetchImpl });
  await assert.rejects(
    () => api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 }),
    (err) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.code, 'quota_exceeded');
      assert.equal(err.status, 429);
      assert.equal(err.requestId, 'r-1');
      assert.equal(err.retryAfter, '60');
      assert.match(err.message, /hosted runners share egress addresses/);
      return true;
    },
  );
});

test('a non-JSON error body still yields a usable code', async () => {
  const fetchImpl = stubFetch({
    ok: false,
    status: 502,
    text: async () => '<html>bad gateway</html>',
    headers: { get: () => null },
  });
  const api = new ApiClient({ baseUrl: 'https://api.example.test', fetchImpl });
  await assert.rejects(
    () => api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 }),
    (err) => err.code === 'http_502' && /the API answered 502/.test(err.message),
  );
});

test('a 2xx without a locator is an error, not a silent success', async () => {
  const fetchImpl = stubFetch(ok({ ok: true }));
  const api = new ApiClient({ baseUrl: 'https://api.example.test', fetchImpl });
  await assert.rejects(
    () => api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 }),
    /returned no locator/,
  );
});

test('an unreachable API is a NetworkError, with code "network"', async () => {
  const api = new ApiClient({
    baseUrl: 'https://api.example.test',
    fetchImpl: async () => {
      throw new Error('getaddrinfo ENOTFOUND');
    },
  });
  await assert.rejects(
    () => api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 }),
    (err) => {
      assert.ok(err instanceof NetworkError);
      assert.equal(err.code, 'network');
      assert.match(err.message, /cannot reach https:\/\/api\.example\.test/);
      return true;
    },
  );
});

test('a hung API aborts rather than holding the job open', async () => {
  const api = new ApiClient({
    baseUrl: 'https://api.example.test',
    timeoutMs: 10,
    fetchImpl: (url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      }),
  });
  await assert.rejects(
    () => api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 }),
    /timed out after 10 ms/,
  );
});

test('no token means no Authorization header at all, not an empty one', async () => {
  const fetchImpl = stubFetch(ok(created));
  const api = new ApiClient({ baseUrl: 'https://api.example.test', fetchImpl });
  await api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 });
  assert.ok(!('authorization' in fetchImpl.calls[0].init.headers));
});

test('a token is sent as a bearer credential', async () => {
  const fetchImpl = stubFetch(ok(created));
  const api = new ApiClient({ baseUrl: 'https://api.example.test', fetchImpl, token: 'eyJhbGc' });
  await api.createSecret({ ciphertextB64: 'x', sizeBytes: 1, oneTime: true, expiresInDays: 1 });
  assert.equal(fetchImpl.calls[0].init.headers.authorization, 'Bearer eyJhbGc');
});
