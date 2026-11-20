"""Re-runnable proof that the action's tests actually fail when the code breaks.

The CLI ships `cli/tools/mutation-check.py` for the same reason: a run that
says "N seeded defects, N caught" leaves a number in a commit message that
nobody can check afterwards. This file is that claim, as a command.

Each case rewrites one line of `action/src/*.js` into a plausible wrong
version, runs `node --test test/`, and expects a non-zero exit. The source is
restored whatever happens. Two of these cases exist because an acceptance
reviewer found them surviving: `process.exitCode = 0` in `main.js`, and a typo
in the `$GITHUB_OUTPUT` environment variable name — both of which left the
entire suite green until `test/integration.test.js` was written.

Run:  python action/tools/mutation-check.py          (from the repository root)
      python action/tools/mutation-check.py --list
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ACTION = Path(__file__).resolve().parents[1]
REPO = ACTION.parent
SRC = ACTION / "src"

# (file, what the source says, what the mutant says, what it would break)
MUTATIONS: list[tuple[str, str, str, str]] = [
    ("main.js",
     "process.exitCode = code;",
     "process.exitCode = 0;",
     "every failed step reports success"),
    ("run.js",
     "const path = env.GITHUB_OUTPUT;",
     "const path = env.GITHUB_OUTPUTS;",
     "the link is never written anywhere and the secret is unreachable"),
    ("run.js",
     "if (config.mask) emit(maskLine(keyFragment));",
     "",
     "the key is not masked before the request"),
    ("run.js",
     "      emit(maskLine(created.locator));",
     "",
     "the locator is left readable, and a locator alone can burn the secret"),
    ("run.js",
     "  if (v === 'false') return false;",
     "  return false;",
     "`one-time: yes` silently means false"),
    ("run.js",
     "readInput(env, 'secret', { trim: false })",
     "readInput(env, 'secret')",
     "a secret with meaningful whitespace is altered in flight"),
    ("run.js",
     "if (envelope.length > MAX_INLINE_BYTES) {",
     "if (false) {",
     "an oversized value is uploaded instead of refused"),
    ("run.js",
     "  const token = parseToken(readInput(env, 'api-token'));",
     "  const token = readInput(env, 'api-token');",
     "a token pasted with its `Bearer ` prefix produces a silent 401"),
    ("api.js",
     "      ciphertext: ciphertextB64,",
     "      ciphertext: ciphertextB64,\n      repository: process.env.GITHUB_REPOSITORY ?? '',",
     "the caller's repository name is sent to the service"),
    ("api.js",
     "          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),",
     "          authorization: `Bearer ${this.token}`,",
     "an anonymous call sends an empty credential"),
    ("workflow.js",
     "return String(value).replace(/%/g, '%25')",
     "return String(value).replace(/%%/g, '%25')",
     "a value can break out of its own workflow command"),
    ("workflow.js",
     "  if (/[\\r\\n]/.test(value)) {",
     "  if (false) {",
     "a multi-line value is masked line by line"),
    ("run.js",
     "    zeroize(key);",
     "",
     "the key is left in memory after the run"),
    ("vendor/crypto.js",
     "  envelope.set(iv, 0);\n  envelope.set(tag, IV_BYTES);",
     "  envelope.set(tag, 0);\n  envelope.set(iv, IV_BYTES);",
     "the envelope layout drifts and no link decrypts"),
]


def run_suite() -> int:
    """Both halves of the action's gate, because the mutants do not respect the split.

    The node suite is the behaviour; `work/ops/tests/test_gh_action.py` holds
    the properties a running test cannot observe — the vendored envelope
    matching the CLI's, action.yml agreeing with the code, and the two or three
    lines whose only observable effect is their absence. Measuring only the
    node half once reported a surviving mutant that the Python half catches
    immediately, which is a worse answer than either suite alone.
    """
    node = subprocess.run(
        ["node", "--test", "test/"],
        cwd=ACTION, capture_output=True, text=True, timeout=300, shell=False,
    )
    if node.returncode != 0:
        return node.returncode
    gate = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
         str(REPO / "work" / "ops" / "tests" / "test_gh_action.py")],
        cwd=REPO, capture_output=True, text=True, timeout=300, shell=False,
    )
    return gate.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print the cases and stop")
    args = parser.parse_args()

    if args.list:
        for name, old, _new, why in MUTATIONS:
            print(f"{name}: {why}  [{old.strip()[:60]}]")
        return 0

    if run_suite() != 0:
        print("the suite is already failing; fix that before measuring mutations")
        return 2

    missed: list[str] = []
    for name, old, new, why in MUTATIONS:
        path = SRC / name
        source = path.read_text(encoding="utf-8")
        if old not in source:
            print(f"ANCHOR LOST  {name}: {old.strip()[:60]!r} is not in the file")
            missed.append(f"{name} (anchor lost)")
            continue
        path.write_text(source.replace(old, new, 1), encoding="utf-8", newline="")
        try:
            code = run_suite()
        finally:
            path.write_text(source, encoding="utf-8", newline="")
        if code == 0:
            print(f"MISSED   {name}: {why}")
            missed.append(f"{name}: {why}")
        else:
            print(f"caught   {name}: {why}")

    print(f"\n{len(MUTATIONS) - len(missed)}/{len(MUTATIONS)} caught")
    if missed:
        print("SURVIVING MUTANTS — the suite does not test what it claims to:")
        for item in missed:
            print(f"  - {item}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
