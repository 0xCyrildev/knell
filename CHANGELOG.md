# Changelog

All notable changes to knell are documented here. The format follows
Keep a Changelog; knell aims at Semantic Versioning, and the promise that
versioning protects is the exit-code contract in `docs/DESIGN.md`.

## [0.1.1] - 2026-10-14

`--quiet` now also silences the logger. The logger writes to stderr and cron turns
stderr into mail, so a routine `knell check --quiet` was announcing every state
transition it recorded — noise where the exit code is the signal.

Documented that `knell status` carries the verdict in its own exit code
(`knell status || notify` works; use `|| true` for a pure report), with a test that
pins it. CI's smoke step fixed accordingly.

## [0.1.0] - 2026-10-14

First public release.

### Added

- `knell add|beat|check|status|list|history|alerts|token|rotate|sign|verify|gc|pause|resume|rm|serve|init|ping|version`
- Signed beacons: HMAC-SHA256 over `knell-v1\n<slug>\n<unix-seconds>\n<nonce>\n`,
  checked with a constant-time compare inside a configurable skew window (15m).
- Two-layer replay defence: an in-memory nonce cache for the current process and
  a durable `UNIQUE(slug, nonce)` constraint that survives a restart.
- Liveness states `ok`, `late`, `silent`, `never`, `paused` with the exit-code
  contract 0 / 1 / 2, plus `--strict` and `--ignore`.
- `knell beat <slug> -- <command>`: check in on a job's behalf, propagating the
  job's own exit code, with `--on success|failure|always`.
- HTTP collector with per-client token-bucket rate limiting, body limits, request
  timeouts, graceful shutdown, `/healthz`, `/metrics` and an admin API that stays
  disabled unless `KNELL_ADMIN_TOKEN` is present.
- Signing secrets in a separate 0600 keyring file, not the database, so a database
  backup is not a key backup.
- `knell verify`: recompute every stored beacon's signature to detect invented
  check-ins; key rotation keeps one previous key so old beacons stay verifiable.
- Notify hooks with alert data passed only through environment variables.
- Retention: `knell gc` and an automatic prune that always keeps the newest beacons
  per check, so a long-dead job reports `silent since …` rather than `never`.
- Terminal and JSON output for every report; `--json` shapes are shared with the
  HTTP API.
- Makefile, multi-stage non-root Dockerfile, GitHub Actions CI.
