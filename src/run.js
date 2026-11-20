/**
 * What the action actually does, with every edge it touches injected.
 *
 * `main.js` supplies the real process; the tests supply a fake environment, a
 * fake `fetch` and a string buffer for stdout, so the assertions that matter —
 * the plaintext never leaves the runner, the key is masked before the first
 * network call, the link is masked before it is written anywhere — are
 * assertions about bytes rather than about intentions.
 */

import { appendFile } from 'node:fs/promises';

import {
  MAX_INLINE_BYTES,
  encryptTextToEnvelope,
  generateKey,
  toBase64Url,
  zeroize,
} from './vendor/crypto.js';
import { buildLink } from './vendor/link.js';
import { ApiClient } from './api.js';
import { errorLine, maskLine, noticeLine, outputEntry, readInput, warningLine } from './workflow.js';

export const VERSION = '0.1.0';

/** The longest expiry the API accepts; the CLI enforces the same ceiling. */
export const MAX_DAYS = 30;

const DEFAULT_API_BASE = 'https://api.easytopaste.com';
const DEFAULT_APP_BASE = 'https://app.easytopaste.com';

/** A problem with the `with:` block — the caller's to fix, not the API's. */
export class InputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InputError';
    this.code = 'invalid_input';
  }
}

/**
 * Parse the `with:` block into a config, or throw InputError.
 * @param {NodeJS.ProcessEnv} env
 */
export function parseInputs(env) {
  // Untrimmed on purpose: a trailing newline is part of some secrets, and an
  // action that silently rewrites the value it was handed is an action whose
  // output does not decrypt to what the caller put in.
  const secret = readInput(env, 'secret', { trim: false });
  if (secret === '') {
    throw new InputError('`secret` is empty — there is nothing to encrypt.');
  }

  const days = parseDays(readInput(env, 'days') || '1');
  const oneTime = parseBool(readInput(env, 'one-time') || 'true', 'one-time');
  const mask = parseBool(readInput(env, 'mask') || 'true', 'mask');
  const failOnError = parseBool(readInput(env, 'fail-on-error') || 'true', 'fail-on-error');
  const apiBase = parseBase(readInput(env, 'api-base') || DEFAULT_API_BASE, 'api-base');
  const appBase = parseBase(readInput(env, 'app-base') || DEFAULT_APP_BASE, 'app-base');
  const token = parseToken(readInput(env, 'api-token'));

  return { secret, days, oneTime, mask, failOnError, apiBase, appBase, token };
}

function parseDays(value) {
  if (!/^\d+$/.test(value)) {
    throw new InputError(`\`days\` must be a whole number from 1 to ${MAX_DAYS}, got "${value}".`);
  }
  const days = Number(value);
  if (days < 1 || days > MAX_DAYS) {
    throw new InputError(`\`days\` must be from 1 to ${MAX_DAYS}, got "${value}".`);
  }
  return days;
}

function parseBool(value, name) {
  const v = value.toLowerCase();
  if (v === 'true') return true;
  if (v === 'false') return false;
  // Deliberately strict. YAML turns `mask: no` into the string "no", and a
  // lenient parser that treated anything-but-true as false would silently
  // publish a link in clear text the one time somebody typed "yes".
  throw new InputError(`\`${name}\` must be "true" or "false", got "${value}".`);
}

function parseToken(value) {
  if (value === '') return '';
  // Checked in the order a person gets it wrong. Pasting the whole header
  // line — `Bearer eyJ...` — is the common mistake, and the resulting 401
  // says nothing about why.
  if (/^bearer\s/i.test(value)) {
    throw new InputError('`api-token` must be the token alone, without a "Bearer " prefix.');
  }
  if (/\s/.test(value)) {
    throw new InputError('`api-token` must not contain whitespace — pass the token alone.');
  }
  if (/[^!-~]/.test(value)) {
    throw new InputError('`api-token` contains characters that cannot appear in an HTTP header.');
  }
  return value;
}

function parseBase(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new InputError(`\`${name}\` is not a URL: "${value}".`);
  }
  const localhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && localhost)) {
    throw new InputError(
      `\`${name}\` must be https (http is allowed for localhost only): "${value}".`,
    );
  }
  return value.replace(/\/+$/, '');
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv,
 *   fetchImpl?: typeof fetch,
 *   write: (chunk: string) => void,
 *   appendOutput?: (text: string) => Promise<void>,
 * }} deps
 * @returns {Promise<number>} the process exit code.
 */
export async function run({ env, fetchImpl, write, appendOutput }) {
  const emit = (text) => write(text);
  const writeOutputs = appendOutput ?? makeOutputWriter(env, emit);

  let config;
  try {
    config = parseInputs(env);
  } catch (err) {
    emit(errorLine(`easytopaste: ${err.message}`));
    await writeOutputs(outputEntry('error-code', err.code ?? 'invalid_input'));
    // An unusable `with:` block is always a failure. `fail-on-error` exists so
    // a flaky network or a spent quota does not redden an otherwise good
    // deploy; it is not a licence to ignore a typo in the workflow file.
    return 1;
  }

  const key = generateKey();
  try {
    // The token is masked first of all. If it came from `${{ secrets.X }}`
    // the runner already masks it; if the caller minted it in an earlier step
    // and passed it along, this is the only thing that will.
    if (config.mask && config.token) emit(maskLine(config.token));

    const keyFragment = toBase64Url(key);
    // Before the first network call and before anything else can print it:
    // the runner only redacts values it already knows about, so a value
    // masked after it leaks is not masked at all.
    if (config.mask) emit(maskLine(keyFragment));

    const envelope = await encryptTextToEnvelope(config.secret, key);
    if (envelope.length > MAX_INLINE_BYTES) {
      emit(
        errorLine(
          `easytopaste: ${envelope.length} bytes is over the ${MAX_INLINE_BYTES}-byte inline limit. ` +
            'Share a file through the web app instead.',
        ),
      );
      await writeOutputs(outputEntry('error-code', 'payload_too_large'));
      return config.failOnError ? 1 : 0;
    }

    const api = new ApiClient({
      baseUrl: config.apiBase,
      version: VERSION,
      fetchImpl,
      token: config.token,
    });
    let created;
    try {
      created = await api.createSecret({
        ciphertextB64: toBase64Url(envelope),
        sizeBytes: envelope.length,
        oneTime: config.oneTime,
        expiresInDays: config.days,
      });
    } catch (err) {
      emit(errorLine(`easytopaste: ${err.message}`));
      await writeOutputs(outputEntry('error-code', err.code ?? 'unknown'));
      if (!config.failOnError) {
        emit(warningLine('easytopaste: continuing because `fail-on-error` is false.'));
        return 0;
      }
      return 1;
    }

    const link = buildLink({ locator: created.locator, key, appBase: config.appBase });
    if (config.mask) {
      emit(maskLine(link));
      // The locator is masked too, and not as tidiness. `POST
      // /v1/secrets/{locator}/burn` takes no key and no credential, so a
      // locator on its own is a destroy capability: anyone who can read the
      // workflow log could burn the secret before the recipient opens it.
      // Disclosure needs the key; denial only needs this.
      emit(maskLine(created.locator));
    }

    await writeOutputs(
      outputEntry('link', link) +
        outputEntry('locator', created.locator) +
        outputEntry('expires-at', created.expiresAt ?? '') +
        outputEntry('one-time', String(config.oneTime)) +
        outputEntry('error-code', ''),
    );

    // Says what happened without being a second copy of the secret: no link,
    // no locator, no byte of ciphertext.
    emit(
      noticeLine(
        `easytopaste: encrypted ${envelope.length} bytes in the runner and stored the ciphertext. ` +
          (config.oneTime
            ? `The link is one-time — the first read destroys it — and expires in ${config.days} day(s) regardless. `
            : `The link is re-readable and expires in ${config.days} day(s). `) +
          'It is in this step\'s `link` output' +
          (config.mask ? ', and masked in the log.' : '. Masking is off, so whatever prints it prints it.'),
      ),
    );
    return 0;
  } catch (err) {
    emit(errorLine(`easytopaste: ${err?.message ?? err}`));
    await writeOutputs(outputEntry('error-code', err?.code ?? 'unknown'));
    return config.failOnError ? 1 : 0;
  } finally {
    zeroize(key);
  }
}

/**
 * Append to `$GITHUB_OUTPUT`.
 *
 * Outside a runner that variable is unset; the action still works, it just has
 * nowhere to hand the link, and says so once rather than crashing — which is
 * what running `node src/main.js` locally does.
 */
function makeOutputWriter(env, emit) {
  const path = env.GITHUB_OUTPUT;
  let warned = false;
  return async (text) => {
    if (!path) {
      if (!warned) {
        warned = true;
        emit(
          warningLine(
            'easytopaste: GITHUB_OUTPUT is not set, so step outputs cannot be written. ' +
              'This action is meant to run inside a GitHub Actions job.',
          ),
        );
      }
      return;
    }
    await appendFile(path, text, { encoding: 'utf8' });
  };
}
