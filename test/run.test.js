import test from 'node:test';
import assert from 'node:assert/strict';

import { MAX_INLINE_BYTES, decryptEnvelopeToText, fromBase64Url } from '../src/vendor/crypto.js';
import { parseLink } from '../src/vendor/link.js';
import { VERSION, run } from '../src/run.js';

const LOCATOR = 'MFRGGZDFMZTWQ2LKNNWG23TP';
const EXPIRES = '2026-11-20T21:00:00Z';

/**
 * Drive run() with a fake runner: fake `with:` block, fake fetch, and string
 * buffers standing in for the log and for $GITHUB_OUTPUT.
 */
async function invoke(inputs = {}, { respond, noOutputFile = false } = {}) {
  const env = { GITHUB_OUTPUT: noOutputFile ? undefined : '/dev/null-not-used' };
  for (const [name, value] of Object.entries(inputs)) {
    if (value === undefined) continue;
    env[`INPUT_${name.toUpperCase()}`] = String(value);
  }
  if (noOutputFile) delete env.GITHUB_OUTPUT;

  const log = [];
  const outputs = [];
  const events = [];
  const requests = [];

  const fetchImpl = async (url, init) => {
    events.push('fetch');
    requests.push({ url, init, body: init?.body ? JSON.parse(init.body) : null });
    if (respond) return respond({ url, init });
    return {
      ok: true,
      status: 201,
      text: async () => JSON.stringify({ locator: LOCATOR, expiresAt: EXPIRES }),
      headers: { get: () => null },
    };
  };

  const code = await run({
    env,
    fetchImpl,
    write: (chunk) => {
      log.push(chunk);
      for (const line of chunk.split('\n')) {
        if (line.startsWith('::add-mask::')) events.push('mask');
      }
    },
    appendOutput: noOutputFile ? undefined : async (text) => outputs.push(text),
  });

  return {
    code,
    log: log.join(''),
    events,
    requests,
    outputs: parseOutputs(outputs.join('')),
    masked: log
      .join('')
      .split('\n')
      .filter((l) => l.startsWith('::add-mask::'))
      .map((l) => l.slice('::add-mask::'.length)),
  };
}

/** Parse the heredoc form back into a map, the way the runner does. */
function parseOutputs(text) {
  const result = {};
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^([A-Za-z0-9_-]+)<<(.+)$/.exec(lines[i]);
    if (!match) continue;
    const [, name, delimiter] = match;
    const body = [];
    i += 1;
    while (i < lines.length && lines[i] !== delimiter) {
      body.push(lines[i]);
      i += 1;
    }
    result[name] = body.join('\n');
  }
  return result;
}

test('the happy path: ciphertext out, a working link back, exit 0', async () => {
  const secret = 'hunter2-deploy-key';
  const r = await invoke({ secret });

  assert.equal(r.code, 0);
  assert.equal(r.outputs.locator, LOCATOR);
  assert.equal(r.outputs['expires-at'], EXPIRES);
  assert.equal(r.outputs['one-time'], 'true');
  assert.equal(r.outputs['error-code'], '');
  assert.equal(r.outputs.link, `https://app.easytopaste.com/s/${LOCATOR}#k=${r.masked[0]}&v=1`);
});

test('the link really opens the ciphertext that was uploaded', async () => {
  // The end-to-end property, proved locally: take the envelope the API was
  // given and the key from the link, and get the original value back. A link
  // that does not decrypt is the one failure mode nobody notices until the
  // recipient is already staring at an error.
  const secret = 'correct horse battery staple\nsecond line';
  const r = await invoke({ secret });

  const { key } = parseLink(r.outputs.link);
  const envelope = fromBase64Url(r.requests[0].body.ciphertext, 'ciphertext');
  assert.equal(await decryptEnvelopeToText(envelope, key), secret);
  assert.equal(r.requests[0].body.sizeBytes, envelope.length);
});

test('the plaintext never reaches the log or the request body', async () => {
  const secret = 'SUPER-SECRET-VALUE-9f2a';
  const r = await invoke({ secret });

  assert.ok(!r.log.includes(secret), 'the plaintext appeared in the workflow log');
  assert.ok(
    !JSON.stringify(r.requests[0].body).includes(secret),
    'the plaintext appeared in the request body',
  );
  assert.ok(!r.requests[0].body.ciphertext.includes(secret));
});

test('the key is masked before the first network call, not after', async () => {
  // Ordering is the whole guarantee: the runner only redacts values it was
  // told about *before* they were printed.
  const r = await invoke({ secret: 'x' });
  assert.deepEqual(r.events, ['mask', 'fetch', 'mask', 'mask']);
});

test('the link, the key fragment and the locator are all masked', async () => {
  const r = await invoke({ secret: 'x' });
  const { key } = parseLink(r.outputs.link);
  assert.equal(r.masked.length, 3);
  assert.equal(r.masked[0], r.outputs.link.split('#k=')[1].replace('&v=1', ''));
  assert.equal(r.masked[1], r.outputs.link);
  assert.equal(r.masked[2], LOCATOR, 'the locator alone is enough to burn the secret');
  assert.equal(key.length, 32);
});

test('the key itself never appears in the log outside its mask command', async () => {
  const r = await invoke({ secret: 'x' });
  const fragment = r.masked[0];
  const withoutMasks = r.log
    .split('\n')
    .filter((l) => !l.startsWith('::add-mask::'))
    .join('\n');
  assert.ok(!withoutMasks.includes(fragment));
  assert.ok(!withoutMasks.includes(LOCATOR), 'the notice must not name the locator');
});

test('mask: false emits no mask commands at all', async () => {
  const r = await invoke({ secret: 'x', mask: 'false' });
  assert.equal(r.code, 0);
  assert.equal(r.masked.length, 0);
  assert.match(r.log, /Masking is off/);
});

test('the value is sent exactly as given, trailing newline included', async () => {
  const secret = 'token-with-newline\n';
  const r = await invoke({ secret });
  const { key } = parseLink(r.outputs.link);
  const envelope = fromBase64Url(r.requests[0].body.ciphertext, 'ciphertext');
  assert.equal(await decryptEnvelopeToText(envelope, key), secret);
});

test('one-time: false asks the API for a re-readable secret and says so', async () => {
  const r = await invoke({ secret: 'x', 'one-time': 'false', days: '7' });
  assert.equal(r.code, 0);
  assert.equal(r.requests[0].body.oneTime, false);
  assert.equal(r.requests[0].body.expiresInDays, 7);
  assert.equal(r.outputs['one-time'], 'false');
  assert.match(r.log, /re-readable and expires in 7 day\(s\)/);
});

test('defaults are one-time and one day', async () => {
  const r = await invoke({ secret: 'x' });
  assert.equal(r.requests[0].body.oneTime, true);
  assert.equal(r.requests[0].body.expiresInDays, 1);
});

test('an empty secret fails before any network call', async () => {
  const r = await invoke({ secret: '' });
  assert.equal(r.code, 1);
  assert.equal(r.requests.length, 0);
  assert.equal(r.outputs['error-code'], 'invalid_input');
  assert.match(r.log, /::error::easytopaste: `secret` is empty/);
});

test('days outside 1..30 is rejected', async () => {
  for (const days of ['0', '31', '-1', '1.5', 'seven', '']) {
    const r = await invoke({ secret: 'x', days: days === '' ? undefined : days });
    if (days === '') {
      assert.equal(r.code, 0, 'an unset days must fall back to the default');
      continue;
    }
    assert.equal(r.code, 1, `days=${days} should have been rejected`);
    assert.equal(r.outputs['error-code'], 'invalid_input');
  }
});

test('a boolean input is strict: "yes" is not "true"', async () => {
  const r = await invoke({ secret: 'x', 'one-time': 'yes' });
  assert.equal(r.code, 1);
  assert.match(r.log, /must be "true" or "false", got "yes"/);
});

test('a bad with: block fails the step even when fail-on-error is false', async () => {
  // A typo in the workflow is not a transient condition to shrug off.
  const r = await invoke({ secret: 'x', days: '99', 'fail-on-error': 'false' });
  assert.equal(r.code, 1);
});

test('a plaintext api-base is refused', async () => {
  const r = await invoke({ secret: 'x', 'api-base': 'http://api.example.test' });
  assert.equal(r.code, 1);
  assert.match(r.log, /must be https/);
});

test('http is allowed for localhost, where a self-hoster tests', async () => {
  const r = await invoke({
    secret: 'x',
    'api-base': 'http://localhost:8000',
    'app-base': 'http://127.0.0.1:4200',
  });
  assert.equal(r.code, 0);
  assert.equal(r.requests[0].url, 'http://localhost:8000/v1/secrets');
  assert.ok(r.outputs.link.startsWith('http://127.0.0.1:4200/s/'));
});

test('a trailing slash on an origin does not produce a doubled path', async () => {
  const r = await invoke({ secret: 'x', 'api-base': 'https://api.example.test/' });
  assert.equal(r.requests[0].url, 'https://api.example.test/v1/secrets');
});

test('an API failure fails the step and reports the code', async () => {
  const r = await invoke(
    { secret: 'x' },
    {
      respond: () => ({
        ok: false,
        status: 429,
        text: async () => JSON.stringify({ error: { code: 'quota_exceeded', message: 'spent.' } }),
        headers: { get: () => null },
      }),
    },
  );
  assert.equal(r.code, 1);
  assert.equal(r.outputs['error-code'], 'quota_exceeded');
  assert.ok(!('link' in r.outputs));
});

test('fail-on-error: false turns an API failure into a warning and exit 0', async () => {
  const r = await invoke(
    { secret: 'x', 'fail-on-error': 'false' },
    {
      respond: () => ({
        ok: false,
        status: 500,
        text: async () => JSON.stringify({ error: { code: 'internal', message: 'boom' } }),
        headers: { get: () => null },
      }),
    },
  );
  assert.equal(r.code, 0);
  assert.equal(r.outputs['error-code'], 'internal');
  assert.match(r.log, /::warning::easytopaste: continuing because/);
});

test('a network failure is reported as such', async () => {
  const r = await invoke(
    { secret: 'x' },
    {
      respond: () => {
        throw new Error('ECONNRESET');
      },
    },
  );
  assert.equal(r.code, 1);
  assert.equal(r.outputs['error-code'], 'network');
});

test('an oversized value is refused locally, without uploading anything', async () => {
  const r = await invoke({ secret: 'A'.repeat(MAX_INLINE_BYTES + 1) });
  assert.equal(r.code, 1);
  assert.equal(r.requests.length, 0, 'nothing may be uploaded once the limit is known');
  assert.equal(r.outputs['error-code'], 'payload_too_large');
  assert.match(r.log, /over the 262144-byte inline limit/);
});

test('outside a runner it warns once instead of crashing', async () => {
  const r = await invoke({ secret: 'x' }, { noOutputFile: true });
  assert.equal(r.code, 0);
  const warnings = r.log.split('\n').filter((l) => l.includes('GITHUB_OUTPUT is not set'));
  assert.equal(warnings.length, 1);
});

test('the action reports its own version in the User-Agent', async () => {
  const r = await invoke({ secret: 'x' });
  assert.equal(r.requests[0].init.headers['user-agent'], `easytopaste-action/${VERSION}`);
});

test('an api-token is sent as a bearer credential and masked first of all', async () => {
  const token = 'eyJhbGciOiJSUzI1NiJ9.payload.signature';
  const r = await invoke({ secret: 'x', 'api-token': token });

  assert.equal(r.code, 0);
  assert.equal(r.requests[0].init.headers.authorization, `Bearer ${token}`);
  assert.deepEqual(r.events, ['mask', 'mask', 'fetch', 'mask', 'mask']);
  assert.equal(r.masked[0], token, 'the token must be masked before anything else happens');

  const withoutMasks = r.log
    .split('\n')
    .filter((l) => !l.startsWith('::add-mask::'))
    .join('\n');
  assert.ok(!withoutMasks.includes(token));
});

test('without an api-token the request is anonymous', async () => {
  const r = await invoke({ secret: 'x' });
  assert.ok(!('authorization' in r.requests[0].init.headers));
});

test('a token pasted with its "Bearer " prefix is rejected with that reason', async () => {
  const r = await invoke({ secret: 'x', 'api-token': 'Bearer eyJhbGc' });
  assert.equal(r.code, 1);
  assert.equal(r.outputs['error-code'], 'invalid_input');
  assert.match(r.log, /without a "Bearer " prefix/);
  assert.equal(r.requests.length, 0);
});

test('a token carrying whitespace or control characters is rejected', async () => {
  for (const token of ['two words', 'tab\there']) {
    const r = await invoke({ secret: 'x', 'api-token': token });
    assert.equal(r.code, 1, `"${token}" should have been rejected`);
    assert.match(r.log, /must not contain whitespace/);
  }
});
