# EasyToPaste — one-time secret, from a workflow

Encrypt a value **inside the runner** and get a one-time link back. The key is
generated on the runner, stays on the runner, and travels only in the link's
URL fragment — the part no HTTP client transmits.

What it is: <https://easytopaste.com/?utm_source=github-marketplace&utm_medium=action&utm_campaign=launch-2026-11>
· how the encryption works: <https://easytopaste.com/how-it-works/?utm_source=github-marketplace&utm_medium=action&utm_campaign=launch-2026-11>
· the same thing from a terminal: `npm i -g easytopaste`

The request body carries a ciphertext envelope and a few bytes of
non-sensitive metadata, and nothing else: no plaintext, no key, and nothing
about your repository, workflow, run or actor. Being precise about the rest,
because an HTTP request is never only its body — the service also sees what
any server sees, your runner's egress IP address (that is what the daily
anonymous quota is counted against), and a `User-Agent` of
`easytopaste-action/<version>`, sent on purpose so this surface can be told
apart from the CLI in an access log.

Use it when a job has to hand a human something sensitive: a rotated deploy
key, a first-login password, a recovery code, a signed artifact's passphrase.
Posting it into a Slack message or an issue comment leaves the secret in that
system forever. Posting a one-time link leaves a link that stops working the
moment it is read.

```yaml
- name: Create a one-time link
  id: secret
  uses: Nemet360/easytopaste-action@v1
  with:
    secret: ${{ secrets.ROTATED_DEPLOY_KEY }}
    days: 2

- name: Tell the on-call engineer where it is
  run: |
    curl -sS -X POST "$SLACK_WEBHOOK" \
      --form-string "payload={\"text\":\"New deploy key: $LINK\"}"
  env:
    SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
    LINK: ${{ steps.secret.outputs.link }}
```

## Inputs

| name | default | what it does |
|------|---------|--------------|
| `secret` | — (required) | The value to encrypt. Sent exactly as given, trailing newline included. |
| `days` | `1` | Whole days until it expires on its own, 1–30. |
| `one-time` | `true` | `true` destroys the secret on first read. `false` leaves it readable until it expires. |
| `mask` | `true` | Registers the link, its key fragment and the locator with the runner's log masking. |
| `api-token` | _(empty)_ | Optional bearer access token. Anonymous callers share a daily creation quota keyed to the runner's egress IP. See *Quota* below. |
| `api-base` | `https://api.easytopaste.com` | Override for a self-hosted deployment. |
| `app-base` | `https://app.easytopaste.com` | Override for a self-hosted deployment. |
| `fail-on-error` | `true` | `false` reports the failure in `error-code` and lets the job continue. A malformed `with:` block fails the step either way. |

## Outputs

| name | what it is |
|------|------------|
| `link` | The full one-time link, key fragment included. |
| `locator` | The secret's id. Not enough to decrypt — enough to destroy. |
| `expires-at` | ISO-8601 expiry, or empty if the API reported none. |
| `one-time` | `"true"` if the first read destroys the secret. |
| `error-code` | Empty on success; otherwise `quota_exceeded`, `rate_limited`, `payload_too_large`, `invalid_input`, `network`, … |

## What this action does and does not protect you from

**It encrypts before anything leaves the job.** AES-256-GCM with a fresh
32-byte key per secret, the same envelope the web app and the `easytopaste`
CLI use — `[iv 12][tag 16][ciphertext n]`, base64url, key in the `#k=`
fragment. A link made here opens in a browser; a link made in a browser opens
in the CLI.

**It masks, by default, three values**: the key fragment, the whole link, and
the locator. Masking is a log control, not an access control. A later step
that sends the link somewhere sends the real link — that is the point — but
`run: echo ${{ steps.secret.outputs.link }}` prints `***`.

The locator is masked too, and not for tidiness. `POST
/v1/secrets/{locator}/burn` takes no key and no credential: anyone who can read
the locator can destroy the secret before its recipient opens it. Disclosure
needs the key; denial needs only the id.

**It does not mask your plaintext.** If you pass a literal instead of a
`secret`, that literal is in your workflow file and in the runner's
environment, and this action does not change that. Pass `${{ secrets.X }}` or a
previous step's masked output.

**It does not protect you from your own workflow.** `pull_request_target`,
a self-hosted runner shared with untrusted jobs, or a step that writes the link
into a job summary will each hand the secret to someone. The action cannot see
any of that.

## Quota

**Anonymous creates are capped at 10 per day, per egress IP.** Hosted GitHub
runners share egress addresses, so a busy organisation can exhaust that
allowance and see `error-code: quota_exceeded`. It is a service limit, not a
bug in this action — and it was measured, not assumed: the first live run of
this action hit exactly that cap.

`api-token` raises it, but read the shape of it before you plan around it:
EasyToPaste has **no long-lived API key today**. Access tokens are RS256 and
last 15 minutes; refresh tokens last 30 days and rotate on every use, so a
refresh token parked in a repository secret is wrong after its first use.
Realistically `api-token` is for a workflow that logs in during an earlier
step, or for a self-hosted deployment. A machine credential that a CI job can
hold is a product gap, and it is written down as one.

## Dependencies

None. Not "few" — the `node_modules` directory does not exist, `action.yml`
points straight at `src/main.js`, and the whole action is readable in one
sitting. A tool that handles your deploy keys should be one you can audit, and
`@actions/core` would have put a transitive dependency tree in the same process
as your plaintext for the sake of four stdout commands and one append-only
file.

## Licence

See [LICENSE.md](LICENSE.md). Free to use, including commercially and inside
CI. Not an open-source maintenance promise.

Questions: <https://easytopaste.com/legal/contact>
