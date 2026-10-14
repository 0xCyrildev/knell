#!/usr/bin/env bash
# Build a realistic knell state in a temp directory, capture four sessions as text,
# and render them to PNGs for the README. Every line in the screenshots is real
# output from the binary — this script only decides what to run, never what to print.
#
#   make build && ./tools/demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KNELL="${KNELL:-$ROOT/bin/knell}"
export KNELL
[ -x "$KNELL" ] || { echo "build first: make build" >&2; exit 1; }

WORK="${WORK:-/tmp/knell-demo}"
SCENES="$WORK/scenes"
ASSETS="$ROOT/docs/assets"
PORT="${PORT:-18500}"

rm -rf "$WORK"; mkdir -p "$SCENES" "$ASSETS"
export KNELL_DB="$WORK/knell.db" KNELL_KEYS="$WORK/keys.json" KNELL_CONFIG="$WORK/config.json"

"$KNELL" init >/dev/null

# A fleet that looks like someone's actual crontab.
"$KNELL" add nas-health     --period 10m  --grace 3m  --note 'smartctl + zfs scrub on nas0' >/dev/null
"$KNELL" add nightly-dump   --period 6h   --grace 30m --note 'pg_dump to cold storage' >/dev/null
"$KNELL" add ci-pipeline    --period 15m  --grace 5m  --note 'main branch build' >/dev/null
"$KNELL" add cache-warm     --period 30m  --grace 5m  --note 'redis preheat' >/dev/null
"$KNELL" add deploy-staging --period 20m  --grace 5m  --note 'argocd sync watcher' >/dev/null
"$KNELL" add weekly-report  --period 168h --grace 24h --note 'email to team' >/dev/null

for s in nas-health nightly-dump ci-pipeline cache-warm deploy-staging weekly-report; do
	"$KNELL" beat "$s" >/dev/null
done
"$KNELL" pause weekly-report --note 'holiday freeze' >/dev/null

# Let time pass, as if the operator came back in the morning.
sqlite3 "$KNELL_DB" "
UPDATE beacons SET ts=ts-26*60, received_at=received_at-26*60 WHERE slug='ci-pipeline';
UPDATE beacons SET ts=ts-34*60, received_at=received_at-34*60 WHERE slug='cache-warm';
UPDATE beacons SET ts=ts-41*60, received_at=received_at-41*60 WHERE slug='deploy-staging';
UPDATE beacons SET ts=ts-3*3600, received_at=received_at-3*3600 WHERE slug='nightly-dump';
UPDATE checks  SET created_at=created_at-2*86400;
DELETE FROM alerts;"

"$KNELL" serve --addr "127.0.0.1:$PORT" --interval 1s --log-level error >"$WORK/serve.log" 2>&1 &
SRV=$!
trap 'kill -TERM $SRV 2>/dev/null || true' EXIT
sleep 3

# run prints the command, executes it, and shows the real exit code — the point of
# the screenshots is the contract, so it must not be a hand-typed number.
run() {
	local out rc
	echo "$ knell $*"
	if out=$("$KNELL" "$@" 2>&1); then rc=0; else rc=$?; fi
	[ -n "$out" ] && printf '%s\n' "$out"
	[ "$rc" != 0 ] && echo "exit $rc"
	echo
}

# Scene 1: the contract cron and CI depend on.
{
	run beat ci-pipeline
	run check --all
	run check nas-health nightly-dump --quiet
	run check deploy-staging --quiet
	echo '# that 1 is the whole product: nothing failed, something just stopped talking.'
} >"$SCENES/one.txt" 2>&1

# Let the recovery land in the alert trail before the status shot.
sleep 2

# Scene 2: the report a human reads.
{
	run status
} >"$SCENES/two.txt" 2>&1

# Scene 3: signing pays off. A clean database, so "verified" means what it says —
# the aged rows above were backdated with SQL, which by design breaks their HMACs.
VDB="$WORK/verify.db" VK="$WORK/verify-keys.json"
{
	echo '$ knell add nightly-dump --period 6h && knell beat nightly-dump'
	KNELL_DB="$VDB" KNELL_KEYS="$VK" "$KNELL" add nightly-dump --period 6h >/dev/null
	KNELL_DB="$VDB" KNELL_KEYS="$VK" "$KNELL" beat nightly-dump >/dev/null
	run_verify() {
		local out rc
		echo "$ knell $*"
		if out=$(KNELL_DB="$VDB" KNELL_KEYS="$VK" "$KNELL" "$@" 2>&1); then rc=0; else rc=$?; fi
		[ -n "$out" ] && printf '%s\n' "$out"
		[ "$rc" != 0 ] && echo "exit $rc"
		echo
	}
	run_verify verify
	echo '# someone with write access to the database copy invents a check-in:'
	echo '$ sqlite3 knell.db "UPDATE beacons SET nonce = ..." -- a row no key can sign'
	nonce=$(sqlite3 "$VDB" "SELECT nonce FROM beacons LIMIT 1")
	sqlite3 "$VDB" "UPDATE beacons SET nonce = 'ffffffffffffffffffffffffffffffff' WHERE nonce = '$nonce'"
	run_verify verify
	echo '# knell verify recomputes every stored beacon against the keys it holds.'
} >"$SCENES/three.txt" 2>&1

# Scene 4: the network face.
{
	echo "\$ knell serve --addr 127.0.0.1:$PORT --interval 1s &"
	echo
	run ping --url "http://127.0.0.1:$PORT/healthz"
	run beat --url "http://127.0.0.1:$PORT" ci-pipeline --note 'rebuilt after the fix'
	echo "\$ curl -sS localhost:$PORT/metrics | grep ^knell"
	curl -sS --noproxy '*' "http://127.0.0.1:$PORT/metrics" | grep -E '^knell_(checks|beacons)' || true
} >"$SCENES/four.txt" 2>&1

kill -TERM $SRV 2>/dev/null || true
wait $SRV 2>/dev/null || true
trap - EXIT

python3 "$ROOT/tools/render_shot.py" "$SCENES/one.txt"   "$ASSETS/knell-check.png"   --title 'the contract: silence is the alert'
python3 "$ROOT/tools/render_shot.py" "$SCENES/two.txt"   "$ASSETS/knell-status.png"  --title 'knell status'
python3 "$ROOT/tools/render_shot.py" "$SCENES/three.txt" "$ASSETS/knell-verify.png"  --title 'knell verify — tamper evidence'
python3 "$ROOT/tools/render_shot.py" "$SCENES/four.txt"  "$ASSETS/knell-serve.png"   --title 'knell serve'

echo "scenes: $SCENES   images: $ASSETS"
