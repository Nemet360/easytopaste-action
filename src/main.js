/**
 * Entry point named by `action.yml` (`runs.main`).
 *
 * Nothing but wiring: the runner's real process is handed to `run()`, which is
 * where the behaviour and the tests live.
 */

import { run } from './run.js';

const code = await run({
  env: process.env,
  fetchImpl: globalThis.fetch,
  write: (chunk) => process.stdout.write(chunk),
});

process.exitCode = code;
