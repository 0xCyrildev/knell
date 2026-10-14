# Design

What knell promises, and why it is built this way. The README says how to use it;
this file says what would break the promise.

## The problem, stated exactly

A cron job, a CI pipeline, an agent loop or a systemd timer can fail in a way that
is invisible from the inside: the job does not run, the box is off, the crontab line
was deleted, the script exits non-zero into a `/dev/null`, or the mail nobody reads
went to a mailbox nobody opens. `knell` inverts the question. Instead of asking "did
the job succeed?", it asks the only question that survives all those failure modes:

> **when did this thing last speak?**

That is a dead man's switch. The absence of evidence becomes the evidence.

## Non-goals

- Not a job runner. knell never starts, retries or schedules your work.
- Not an APM or metrics pipeline. It records liveness, not duration, throughput or
  error rates, though it exposes counters about its own behaviour.
- Not a notification product. It records what went quiet and hands one shell command
  the details; getting that to Slack or mail is your command's job.
- Not a secrets manager. Per-check signing keys are stored in a file with 0600
  permissions and nothing more sophisticated.

## State model

Each check has a `period` (how often a beacon is expected) and a `grace` (slack before
an absence becomes an alert). With the last beacon at `L`, now `N`:

| state | condition | meaning |
|---|---|---|
| `ok` | `N <= L + period` | on schedule |
| `late` | `L + period < N <= L + period + grace` | missed, still forgiven |
| `silent` | `N > L + period + grace` | the alert condition |
| `never` | no beacon yet, and `N <= created + period + grace` | configured, awaiting first check-in |
| `paused` | `Paused` is set | deliberate silence, never alerts |

`late` is a state and not a failure by default because grace exists precisely to
absorb jitter; `--strict` promotes it. `never` becomes `silent` on its own, so a check
that was configured and then ignored is eventually reported rather than left ambiguous.

A beacon is attributed to its **claimed** timestamp, not the arrival time. Signing
bounds that claim to the skew window, so the claimed time is authenticated rather than
merely believed. Arrival time is recorded alongside it (`received_at`) so a host with a
broken clock is visible in the data instead of silently shifting everyone's deadlines.

### The exit-code contract

This is the part other software depends on, so it is the part versioning protects.

| code | meaning |
|---|---|
| `0` | every check asked about is inside its grace window |
| `1` | at least one check is `silent` |
| `2` | knell could not decide: bad flags, unreadable state, **a slug that is not configured**, or **nothing to check at all** |

`2` for an unknown name and `2` for an empty set are deliberate. If `knell check
backups` returned `0` after a typo, or after someone renamed the check, the crontab line
would be green forever and the job would be genuinely unsupervised — and the same is true
one level up, if the `checks` table was wiped or `--ignore` matched everything. Silence
about silence is the failure mode this tool exists to prevent, so knell refuses to answer
rather than answer "fine".

`knell beat <slug> -- <command>` keeps the wrapped job's contract, with one exception:

| case | exit |
|---|---|
| job succeeded, check-in landed | `0` |
| job failed | the job's own code (a signal death becomes `1`) |
| job succeeded but the check-in did not land | `2` — the job is fine, the monitoring is not |
| no job wrapped, check-in failed | `1` |

`--quiet` suppresses knell's own chatter and never the wrapped command's stdout, because
cron mails whatever the command printed and that is often the only output a failed backup
ever produces.

`knell beat slug -- <command>` never redefines the job's result: the table above is the
whole rule, and the reason a monitoring failure gets `2` rather than `1` is that a cron
reader must be able to tell "your backup broke" from "your backup is fine and nothing is
watching it".

## Beacons

The signed message is:

```
"knell-v1" "\n" slug "\n" unix-seconds "\n" nonce "\n"
```

and the signature is `HMAC-SHA256(key, that)`, hex, lowercase.

- **Newline delimiters plus a restricted slug charset** (`^[a-z0-9][a-z0-9._-]{0,63}$`)
  and a hex nonce mean no field can contain the delimiter, so no two different triples
  can canonicalise to the same bytes. The slug charset is also what makes slugs safe in
  URL paths, database rows, log lines and pasted shell examples.
- **The version prefix** means a future scheme cannot be confused with this one.
- **Headers, not query parameters.** `Knell-Timestamp`, `Knell-Nonce`,
  `Knell-Signature`. URLs land in proxy logs, load balancer logs and browser history;
  headers usually do not. knell's own access log writes method, path, status, latency,
  peer, slug and rejection reason — and no header values.
- **Constant-time comparison**, after a format check that forces both sides to be 64
  lowercase hex characters, so the compare never has unequal lengths to leak.

### Replay

A valid beacon is reusable until its timestamp leaves the skew window, so two layers
stop it:

1. an in-memory nonce cache holding every accepted `slug|nonce` for the window;
2. a durable `UNIQUE (slug, nonce)` index on the beacon table.

Layer 1 is fast and per-process. Layer 2 is what makes replay survive a restart, a
crash, or an attacker who waits for the cache to roll over. A refused replay writes no
row and returns `409` with `reason: replay` or `replay_durable` so operators can tell
which layer caught it. The cache **refuses when full** rather than evicting: forgetting
a nonce is exactly the failure the cache exists to prevent.

### Rotation

`knell rotate` mints a new key and keeps the previous one. This is not bookkeeping for
its own sake: beacons are immutable evidence about the past, and a verifier that only
knows the current key would report every pre-rotation beacon as forged after a routine
rotation. `knell verify` therefore tries the current key, then the previous one, and
reports `verified`, `old-key`, `unsigned` and `FORGED` separately.

## Storage

One SQLite file, `PRAGMA user_version` at 1, WAL journal, `busy_timeout(5000)`,
`synchronous(NORMAL)`, and one open writer connection so writes are serialised inside
the process. The state file and its WAL sidecars are tightened to `0600` on open, and
their directory to `0700`, because the umask a cron job inherits is often `0022` and
that would leave every check, beacon and note readable by other local users. Three
tables: `checks`, `beacons` (cascading from `checks`), `alerts`.

**Keys are in a separate file, on purpose.** The database is the artifact people back
up, attach to bug reports, mount into other containers and copy to a laptop. If signing
keys lived in it, every routine backup would be a copy of every key that can mint new
beacons. The keyring is a 0600 JSON file that a `.gitignore` and a backup policy can
reasonably treat as a secret. OpenKeys tightens the mode if a stray umask made the file
group-readable, and refuses to open a keyring written by a newer knell. A live collector
re-reads the keyring when its mtime or size changes, so `knell add` and `knell rotate` —
which are separate processes — take effect without a restart; without that, every check
created after the server started would reject its own beacons forever, and rotation could
not revoke a leaked key at all.

Retention (`gc`) always keeps the newest N beacons **per check** regardless of age.
Without that rule, pruning a check that has been dead for months would delete its last
beacon and the report would change from "silent since March" to "never reported" — a
different diagnosis, and the wrong one, at exactly the moment someone is reading it.

## HTTP surface

| route | auth | purpose |
|---|---|---|
| `POST /api/v1/beat/{slug}` | signed beacon | the only unauthenticated write |
| `GET /healthz` | none | is this server up |
| `GET /metrics` | rate-limited | Prometheus text format |
| `GET /api/v1/status` | bearer | verdicts, as JSON |
| `GET /api/v1/checks` | bearer | configuration, key fingerprints only |
| `POST /api/v1/checks` | bearer | create a check, return its new secret once |
| `DELETE /api/v1/checks/{slug}` | bearer | delete a check, its history and its key |

The bearer token comes from `KNELL_ADMIN_TOKEN` **only** — never from the config file —
and when it is unset the admin routes return `503` and say how to enable them. A route
that silently runs open because someone forgot an environment variable would be worse
than a route that refuses. Wrong tokens are rate-limited per address like beacons are,
so probing the credential costs the prober something.

TLS is deliberately out of scope: bind to loopback and terminate it in a reverse proxy
or sidecar, which already has certificates, renewal and ACLs.

**There is no unsigned beacon mode, from any address.** An earlier design admitted
unsigned beacons from loopback peers, and it was removed: "did this packet arrive from
the localhost" is not a capability check. The deployment this document recommends — a
TLS sidecar on the same host — makes *every* internet client a loopback peer, so that
mode was remote check-in forgery waiting to be configured. A check-in that cannot be
signed should be written by `knell beat` into the local database, which is what a
single-host user does anyway. `/metrics` reports the verdicts from the last sweep rather
than re-evaluating every check per scrape, so a polling dashboard cannot push thousands
of rows through the single SQLite writer and delay beacons behind it.

## Alerting

`serve` sweeps every `eval_interval` (default 30s), evaluates all checks with the same
pure function the CLI uses, and compares each result against the last state it
remembered. Transitions into `silent` and out of it become rows in `alerts` and, if
`notify_cmd` is set, one execution of that command with:

```
KNELL_ALERT=silent|recovered|first_beacon
KNELL_SLUG=<slug>
KNELL_DETAIL=<one line of context>
KNELL_ALERT_AT=<RFC3339>
```

The remembered previous state only suppresses duplicate notifications; it never decides
the current state. And a process with no remembered state at all — every `knell check`
run, every collector restart — consults the `alerts` table instead of assuming the outage
was already announced: it re-logs and re-notifies only once the silence has outlasted the
check's own window. That is a nag on an ongoing outage, not an echo repeated by a cron
entry that runs every minute.

Hook details travel only in environment variables, never interpolated into the shell
string, so a value that came from a beacon cannot become shell syntax. The hook inherits
a curated environment (`PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`, `TZ`) rather than the
server's own, so `KNELL_ADMIN_TOKEN` is not handed to a child process.

Beacon handlers accept at most 4 KiB of body, per client address, and the free-text
`note` is capped at 200 runes with control characters (including `ESC`) dropped —
because that note is later printed to a terminal by `knell status`, and an escape
sequence in a stored string is an injection into whoever reads the report.

## Clocks

Since a beacon's timestamp is authenticated and bounded to ±15 minutes by default, a
sending host whose clock is wrong will either be refused (408, loudly, in the CLI) or
will silently shift its own deadlines by up to the skew. Widen the window only if you
understand that a captured beacon then stays reusable for that long — the config
validation refuses anything over 24 hours outright.

## Testing

- Known-answer vectors for the signature, computed with OpenSSL outside the codebase, so
  changing the canonical message breaks a test rather than agreeing with itself.
- Boundary tests on the skew window (exactly at the limit, one second past, future-side).
- Store tests that prove replay is refused twice over, that cascade delete leaves nothing
  behind, and that `gc` keeps evidence for dead checks.
- HTTP tests that assert the **status code on the wire**, plus a test that the access log
  contains no signing material. An earlier version of the response wrapper recorded the
  code without forwarding it, so every rejection looked like `200 OK` to cron while the
  log said the truth; that class of bug is why these are wire tests, not unit tests.
- CLI tests that advance knell's own clock rather than editing stored beacons, because
  backdating a row would make later tests measure their own forgery.
- Client tests that count attempts, so "retries transient failures, never retries a
  rejection" is observed rather than assumed.
- Everything runs under `-race`.
