import test from 'node:test';
import assert from 'node:assert/strict';

import {
  commandLine,
  escapeData,
  escapeProperty,
  errorLine,
  maskLine,
  noticeLine,
  outputEntry,
  readInput,
} from '../src/workflow.js';

test('escapeData encodes the three characters that would end a command', () => {
  assert.equal(escapeData('a%b\rc\nd'), 'a%25b%0Dc%0Ad');
});

test('escapeData encodes % first, so an encoded value is not double-decoded', () => {
  // '%0A' typed by a human must survive as '%250A', not become a newline.
  assert.equal(escapeData('%0A'), '%250A');
});

test('escapeProperty also encodes the property separators', () => {
  assert.equal(escapeProperty('a:b,c'), 'a%3Ab%2Cc');
});

test('commandLine renders properties only when they carry a value', () => {
  assert.equal(commandLine('notice', 'hi'), '::notice::hi\n');
  assert.equal(commandLine('notice', 'hi', { title: 'T' }), '::notice title=T::hi\n');
  assert.equal(commandLine('notice', 'hi', { title: '' }), '::notice::hi\n');
});

test('a multi-line message cannot break out of its own command', () => {
  const line = errorLine('first\nsecond');
  assert.equal(line, '::error::first%0Asecond\n');
  assert.equal(line.split('\n').length, 2, 'the command must occupy exactly one line');
});

test('maskLine emits the add-mask command', () => {
  assert.equal(maskLine('abc'), '::add-mask::abc\n');
});

test('maskLine refuses an empty value, which the runner would silently ignore', () => {
  assert.throws(() => maskLine(''), /empty/);
  assert.throws(() => maskLine(undefined), /empty/);
});

test('maskLine refuses a multi-line value', () => {
  assert.throws(() => maskLine('a\nb'), /multi-line/);
  assert.throws(() => maskLine('a\rb'), /multi-line/);
});

test('noticeLine is a notice', () => {
  assert.equal(noticeLine('done'), '::notice::done\n');
});

test('outputEntry writes the heredoc form a multi-line value needs', () => {
  const entry = outputEntry('link', 'https://x/y#k=z', () => 'DELIM');
  assert.equal(entry, 'link<<DELIM\nhttps://x/y#k=z\nDELIM\n');
});

test('outputEntry picks a different delimiter when the value contains it', () => {
  const delimiters = ['BAD', 'BAD', 'GOOD'];
  const entry = outputEntry('v', 'contains BAD inside', () => delimiters.shift());
  assert.equal(entry, 'v<<GOOD\ncontains BAD inside\nGOOD\n');
});

test('outputEntry gives up rather than emit a block the value can close', () => {
  assert.throws(
    () => outputEntry('v', 'contains BAD inside', () => 'BAD'),
    /cannot find a delimiter/,
  );
});

test('outputEntry rejects a name that is not a legal output name', () => {
  assert.throws(() => outputEntry('a b', 'x', () => 'D'), /not a usable output name/);
  assert.throws(() => outputEntry('a\nb=1', 'x', () => 'D'), /not a usable output name/);
});

test('an empty output value still produces a complete block', () => {
  assert.equal(outputEntry('error-code', '', () => 'D'), 'error-code<<D\n\nD\n');
});

test('readInput finds the dashed env var the runner actually exports', () => {
  // The habit-driven mistake is INPUT_ONE_TIME. The runner does not write that.
  const env = { 'INPUT_ONE-TIME': 'false', INPUT_ONE_TIME: 'true' };
  assert.equal(readInput(env, 'one-time'), 'false');
});

test('readInput trims by default and not when asked not to', () => {
  const env = { INPUT_SECRET: ' hunter2\n' };
  assert.equal(readInput(env, 'secret'), 'hunter2');
  assert.equal(readInput(env, 'secret', { trim: false }), ' hunter2\n');
});

test('a missing input reads as the empty string', () => {
  assert.equal(readInput({}, 'nothing'), '');
});
