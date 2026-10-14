# Security

knell is a monitoring tool whose core primitive is an authenticated event: *a check-in
that someone else cannot forge and cannot replay*. This file says what that protects,
what it does not, and how to report a problem.

## What is defended

**Beacon authenticity.** Every remote check-in is an HMAC-SHA256 over
`knell-v1\n<slug>\n<unix-seconds>\n<nonce>` keyed by a per-check secret. An attacker who
cannot hold the secret cannot invent a check-in, cannot extend a dead job's apparent
life, and cannot retarget one check's beacon at another check (the slug is inside the
signed message). Signatures are compared in constant time after a format check that
forces both operands to be the same fixed length.

**Replay resistance, in two layers.** An in-memory nonce cache for the skew window, and
a durable `UNIQUE (slug, nonce)` constraint. The second layer is why a restart is not a
second chance: a captured beacon that was refused at 14:00 is still refused at 14:05
after the process is replaced. A full cache refuses new nonces rather than evicting live
ones — forgetting is the failure the cache exists to prevent — but it prunes expired
entries first, so one burst of traffic cannot lock honest check-ins out permanently.

**No unsigned network mode exists.** Trusting "this arrived from loopback" is not a
capability check: a TLS sidecar on the same host makes every internet client a loopback
peer, which is the exact deployment the docs recommend. Every beacon over HTTP must be
signed; a check-in that cannot be signed is written to the local database by the CLI
instead, where the file's own permissions are the boundary.

**Clock tolerance is bounded and reported.** A beacon is accepted only within ±15 minutes
(default, configurable, hard-refused above 24h), so a captured beacon has a short shelf
life, and a rejected-for-time beacon returns `408` rather than being quietly accepted.

**Evidence is auditable.** `knell verify` recomputes every stored beacon's signature
against the keys this knell holds (current plus the one it rotated away) and distinguishes
`verified`, `old-key`, `unsigned` and `FORGED`. A database copy can therefore be checked
for invented check-ins without trusting the file that contains them. Exit code 1 when any
row cannot be explained.

**Secrets are separated from the data.** The database holds checks, beacons and alert
history; the signing keys live in a separate file created 0600. A routine database backup
is not a backup of every key that can mint beacons. knell tightens the keyring's mode on
open if a stray umask made it group- or world-readable, and refuses to read a keyring
written by a newer version.

**Nothing secret is ever logged.** The signing material travels in HTTP headers, not the
URL, so it cannot appear in a proxy access log; knell's own log records method, path,
status, latency, peer, slug and rejection reason and no header values. `knell token` and
`--json` mask secrets unless `--reveal` is passed. Metrics carry counts. The admin bearer
token is read only from `KNELL_ADMIN_TOKEN`, never from the config file, so a committed or
backed-up config cannot carry it.

**The admin API fails closed.** With no token configured, admin routes return `503` and
say how to enable them. Token comparison is constant time.

**Injection surfaces are closed by construction.** All SQL values go through parameters;
slugs must match `^[a-z0-9][a-z0-9._-]{0,63}$` before they reach a path, a query, a signed
message or a pasted shell example; free-text notes are capped at 200 runes, kept to
printable characters, and additionally stripped of the bidirectional and zero-width
controls (U+202A–U+202E, U+2066–U+2069, U+200B, U+FEFF) that are *printable* but can make
`knell status` render a slug that is not the stored one — sanitising happens on write, at
every entry point (HTTP note, API create, `--note` flag), not on display; the notify hook
is the operator's own command string, and alert data reaches it only through environment
variables, so a value that came from a beacon cannot become shell syntax.

**Availability limits.** Token-bucket rate limiting per source address on beacons *and*
on admin/metric routes, a request body cap with `413`/`415` distinction, read/header/write/idle
timeouts, `MaxHeaderBytes`, panic recovery that answers `500` and keeps serving, and a
replay cache and limiter map with bounded size.

## Threat model, honestly

| threat | knell's answer | limit |
|---|---|---|
| Forging "the job is alive" from the network | requires the per-check secret | a leaked secret on any host that uses it is a full forgery capability; rotate with `knell rotate` |
| Replaying a captured beacon | skew window + nonce cache + durable unique constraint | inside ±15m, a replay of the *same* nonce is refused; a new nonce needs the key |
| Reading the deployment's traffic | — | knell does not do TLS; terminate it in a reverse proxy. Note that a same-host proxy does **not** make a remote client local: there is no unsigned mode to be fooled by |
| Reading the state files | keyring 0600, database and its directory 0600/0700 | anyone who can run `knell` as you can read your state; knell has no privilege model, so use separate UIDs |
| Someone with write access to the DB | `knell verify` exposes it | they can delete history or add unsigned rows; verification proves what *should* be there, not that nothing was removed |
| DoS on the collector | per-address rate limit, body cap, timeouts, no unbounded state | one process, no auth-based quota; put it behind whatever you rate-limit everything else with |
| A compromised check secret spoofing only one job | one key per check | blast radius is that check, not the deployment |
| Slugs/notes as an injection vector | charset + parameterised SQL + sanitised notes + env-only hook data | alert *details* are built from operator config, not from remote input |

**This is not a security product** and it is not an access-control system. It has no users,
no roles, and one shared admin token. Do not put it on the public internet with the admin
API enabled and no proxy in front of it.

## Reporting

Open a GitHub issue for anything that is a bug in the ordinary sense. For a vulnerability,
please use a private report (GitHub security advisory against the repository) rather than a
public issue, and include: the version from `knell version`, the command or request, what
you expected, and what happened. knell is small enough that a fix usually lands the same
week; the exit-code contract is the one thing that will not change silently, because cron
and CI depend on it.

## Dependency surface

One runtime dependency: `modernc.org/sqlite` (pure Go, so no cgo, no libc, and a static
binary). The crypto is Go standard library: `crypto/hmac`, `crypto/sha256`, `crypto/rand`,
`crypto/subtle`. No telemetry, no outbound calls, no plugin system, nothing that reads your
database over the network.
