/**
 * The GitHub Actions runner protocol, implemented directly.
 *
 * `@actions/core` does all of this, and this action deliberately does not use
 * it. The package pulls a transitive tree at build time, and a GitHub Action
 * is distributed as *committed* JavaScript — so every one of those bytes would
 * end up vendored into the published repository, sitting in the same process
 * as the plaintext of someone's deploy key. The protocol it wraps is four
 * stdout commands and one append-only file. Writing them here keeps the
 * dependency count at zero, which is the same promise the CLI publishes.
 *
 * Reference: the workflow-command format is `::name key=value,key=value::data`,
 * with `%`, CR and LF percent-encoded in both the properties and the data,
 * because a raw newline would end the command and let the remainder of a value
 * be interpreted as the next command.
 */

/**
 * Escape a workflow-command *data* payload.
 * @param {string} value
 * @returns {string}
 */
export function escapeData(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/**
 * Escape a workflow-command *property* value. Properties additionally end at
 * `:` and `,`, so both are encoded.
 * @param {string} value
 * @returns {string}
 */
export function escapeProperty(value) {
  return escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/**
 * A workflow-command line, newline-terminated.
 * @param {string} command
 * @param {string} data
 * @param {Record<string, string>} properties
 */
export function commandLine(command, data = '', properties = {}) {
  const props = Object.entries(properties)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${escapeProperty(v)}`)
    .join(',');
  return `::${command}${props ? ` ${props}` : ''}::${escapeData(data)}\n`;
}

/**
 * The runner's log-masking facility.
 *
 * Everything the runner has been told to mask is replaced with `***` in the
 * log, including values that arrive there indirectly — a later step that
 * echoes `${{ steps.x.outputs.link }}` prints `***`. It is a log control, not
 * an access control: a step that sends the value somewhere still sends the
 * real value, which is exactly what makes the action useful.
 *
 * A masked value must not be empty and must not contain a newline: the runner
 * ignores an empty mask, and masking a multi-line value masks each line
 * separately, which can blank out unrelated text.
 *
 * @param {string} value
 */
export function maskLine(value) {
  if (typeof value !== 'string' || value === '') {
    throw new TypeError('refusing to mask an empty value: the runner would ignore it');
  }
  if (/[\r\n]/.test(value)) {
    throw new TypeError('refusing to mask a multi-line value');
  }
  return commandLine('add-mask', value);
}

/** `::notice::`, `::warning::` and `::error::` lines. */
export const noticeLine = (message) => commandLine('notice', message);
export const warningLine = (message) => commandLine('warning', message);
export const errorLine = (message) => commandLine('error', message);

/**
 * Render one `$GITHUB_OUTPUT` entry in the heredoc form.
 *
 * The single-line `name=value` form breaks on any value containing a newline,
 * and silently: the first line becomes the output and the rest is parsed as
 * further entries. The delimiter is random per call and verified absent from
 * the value, because a value that contains the delimiter would close the block
 * early — the injection this file format exists to prevent.
 *
 * @param {string} name
 * @param {string} value
 * @param {() => string} randomDelimiter Injected so a test can force a collision.
 */
export function outputEntry(name, value, randomDelimiter = defaultDelimiter) {
  if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    throw new TypeError(`"${name}" is not a usable output name`);
  }
  const text = String(value);
  let delimiter = randomDelimiter();
  for (let attempt = 0; text.includes(delimiter); attempt += 1) {
    if (attempt >= 8) {
      throw new Error('cannot find a delimiter absent from the output value');
    }
    delimiter = randomDelimiter();
  }
  return `${name}<<${delimiter}\n${text}\n${delimiter}\n`;
}

function defaultDelimiter() {
  // Not security-critical — it guards against a value closing its own block,
  // and the value is checked against it either way.
  return `ghadelimiter_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

/**
 * Read an action input the way the runner delivers it.
 *
 * The runner exports `with:` keys as `INPUT_<NAME>`, uppercased, spaces turned
 * into underscores and **dashes left alone** — so `one-time` arrives as
 * `INPUT_ONE-TIME`, which is not a legal shell identifier and is easy to get
 * wrong by habit.
 *
 * @param {NodeJS.ProcessEnv} env
 * @param {string} name
 * @param {{trim?: boolean}} opts `trim` defaults to true; the secret itself is read untrimmed.
 */
export function readInput(env, name, { trim = true } = {}) {
  const raw = env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
  if (raw === undefined) return '';
  return trim ? raw.trim() : raw;
}
