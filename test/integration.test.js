/**
 * The two code paths every other test in this directory steps around.
 *
 * `run.test.js` injects `appendOutput` and calls `run()` directly, which is
 * what makes its assertions sharp — and which leaves exactly two things
 * unexecuted: the real `$GITHUB_OUTPUT` writer, and `src/main.js`, the only
 * file GitHub actually runs. An acceptance reviewer proved the gap by
 * mutating `process.exitCode = code` to `= 0` and `env.GITHUB_OUTPUT` to
 * `env.GITHUB_OUTPUTS`: both left the whole suite green, and the second one
 * is the worse of the two — the secret is uploaded, the key is zeroized, the
 * link is never handed to anyone, and the secret sits unreachable until it
 * expires while the log says it is in the step's output.
 *
 * So these tests use a real file and a real child process, against a real
 * local HTTP server. No stub `fetch`, no injected writer.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { decryptEnvelopeToText, fromBase64Url } from '../src/vendor/crypto.js';
import { parseLink } from '../src/vendor/link.js';
import { run } from '../src/run.js';

const execFileAsync = promisify(execFile);
const MAIN = fileURLToPath(new URL('../src/main.js', import.meta.url));
const LOCATOR = 'MFRGGZDFMZTWQ2LKNNWG23TP';

/** A one-endpoint stand-in for the secrets API, on a real socket. */
async function startApi({ status = 201 } = {}) {
  const requests = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    requests.push({ url: req.url, method: req.method, body: raw ? JSON.parse(raw) : null });
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(
      status < 400
        ? JSON.stringify({ locator: LOCATOR, expiresAt: '2026-11-21T00:00:00Z' })
        : JSON.stringify({ error: { code: 'quota_exceeded', message: 'Daily quota reached.' } }),
    );
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  return {
    base: `http://127.0.0.1:${port}`,
    requests,
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function outputPath() {
  const dir = await mkdtemp(join(tmpdir(), 'easytopaste-action-'));
  return join(dir, 'github_output');
}

/** Parse `$GITHUB_OUTPUT` the way the runner does. */
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

test('run() writes a real $GITHUB_OUTPUT file that parses back', async () => {
  const api = await startApi();
  const path = await outputPath();
  try {
    const log = [];
    const code = await run({
      env: {
        INPUT_SECRET: 'real-file-path-secret',
        'INPUT_API-BASE': api.base,
        'INPUT_APP-BASE': 'https://app.easytopaste.com',
        GITHUB_OUTPUT: path,
      },
      write: (chunk) => log.push(chunk),
    });

    assert.equal(code, 0);
    const outputs = parseOutputs(await readFile(path, 'utf8'));
    assert.equal(outputs.locator, LOCATOR);
    assert.equal(outputs['one-time'], 'true');
    assert.equal(outputs['error-code'], '');
    assert.ok(outputs.link.startsWith('https://app.easytopaste.com/s/'));
    assert.ok(!log.join('').includes('GITHUB_OUTPUT is not set'));

    // The link in the file opens the ciphertext the server received.
    const { key } = parseLink(outputs.link);
    const envelope = fromBase64Url(api.requests[0].body.ciphertext, 'ciphertext');
    assert.equal(await decryptEnvelopeToText(envelope, key), 'real-file-path-secret');
  } finally {
    await api.stop();
  }
});

test('a failure still leaves error-code in the real output file', async () => {
  const api = await startApi({ status: 429 });
  const path = await outputPath();
  try {
    const code = await run({
      env: { INPUT_SECRET: 'x', 'INPUT_API-BASE': api.base, GITHUB_OUTPUT: path },
      write: () => {},
    });
    assert.equal(code, 1);
    assert.equal(parseOutputs(await readFile(path, 'utf8'))['error-code'], 'quota_exceeded');
  } finally {
    await api.stop();
  }
});

test('src/main.js exits 0 and fills the output file when it succeeds', async () => {
  const api = await startApi();
  const path = await outputPath();
  try {
    const { stdout } = await execFileAsync(process.execPath, [MAIN], {
      env: {
        ...process.env,
        INPUT_SECRET: 'child-process-secret',
        'INPUT_API-BASE': api.base,
        GITHUB_OUTPUT: path,
      },
    });
    assert.match(stdout, /::add-mask::/);
    assert.ok(!stdout.includes('child-process-secret'));
    assert.equal(parseOutputs(await readFile(path, 'utf8')).locator, LOCATOR);
  } finally {
    await api.stop();
  }
});

test('src/main.js exits NON-ZERO when the run fails', async () => {
  // The mutation this exists for: `process.exitCode = code` -> `= 0` turns
  // every failed step green, in the one file GitHub executes.
  const api = await startApi({ status: 429 });
  const path = await outputPath();
  try {
    await assert.rejects(
      () =>
        execFileAsync(process.execPath, [MAIN], {
          env: {
            ...process.env,
            INPUT_SECRET: 'x',
            'INPUT_API-BASE': api.base,
            GITHUB_OUTPUT: path,
          },
        }),
      (err) => {
        assert.equal(err.code, 1, 'a failed create must exit 1');
        return true;
      },
    );
  } finally {
    await api.stop();
  }
});

test('src/main.js exits non-zero on a malformed with: block, before any network call', async () => {
  const path = await outputPath();
  await assert.rejects(
    () =>
      execFileAsync(process.execPath, [MAIN], {
        env: { ...process.env, INPUT_SECRET: '', GITHUB_OUTPUT: path },
      }),
    (err) => {
      assert.equal(err.code, 1);
      assert.match(err.stdout, /::error::easytopaste: `secret` is empty/);
      return true;
    },
  );
});
