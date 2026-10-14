package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type cli struct {
	a   *app
	out *bytes.Buffer
	err *bytes.Buffer
	dir string
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KNELL_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("KNELL_DB", filepath.Join(dir, "knell.db"))
	t.Setenv("KNELL_KEYS", filepath.Join(dir, "keys.json"))
	// A beacon must not try to reach a server in tests, and a stray environment
	// variable from the developer's shell would do exactly that.
	for _, k := range []string{"KNELL_URL", "KNELL_SECRET", "KNELL_ADMIN_TOKEN", "KNELL_BEACON_MODE", "KNELL_NOTIFY_CMD"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	var out, errb bytes.Buffer
	a := &app{stdout: &out, stderr: &errb, stdin: strings.NewReader("")}
	if err := a.load(); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	return &cli{a: a, out: &out, err: &errb, dir: dir}
}

func (c *cli) run(t *testing.T, args ...string) int {
	t.Helper()
	c.out.Reset()
	c.err.Reset()
	return c.a.run(append([]string{}, args...))
}

func (c *cli) db(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+c.a.cfg.DBPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// advance moves knell's own clock rather than editing stored beacons: a backdated
// row no longer matches its signature, so tampering with history would make every
// later test measure its own forgery instead of the passage of time.
func (c *cli) advance(d time.Duration) {
	base := time.Now()
	c.a.clock = func() time.Time { return base.Add(d) }
}

func TestReorderPutsFlagsFirst(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.Duration("period", time.Hour, "")
	fs.Bool("json", false, "")
	fs.String("note", "", "")
	fs.String("on", "always", "")
	fs.Duration("timeout", time.Second, "")

	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"nightly", "--period", "1h"}, "--period 1h nightly"},
		{[]string{"--period", "1h", "nightly"}, "--period 1h nightly"},
		{[]string{"nightly", "--json"}, "--json nightly"},
		{[]string{"nightly", "--note", "a b", "--json"}, "--note a b --json nightly"},
		{[]string{"--period=30m", "nightly"}, "--period=30m nightly"},
		{[]string{"nightly", "--", "ls", "-la", "--x"}, "nightly -- ls -la --x"},
		{[]string{"beat", "nightly", "--on", "failure", "--", "false"}, "--on failure beat nightly -- false"},
		{[]string{"-h"}, "-h"},
		{[]string{"nightly"}, "nightly"},
	}
	for _, c := range cases {
		got := strings.Join(reorder(fs, c.in), " ")
		if got != c.want {
			t.Errorf("reorder(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestReorderDoesNotLoseTheSlug guards the bug where a flag appearing after the
// slug made `knell add nightly --period 1h` read as four positionals.
func TestReorderDoesNotLoseTheSlug(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.String("period", "", "")
	fs.Bool("quiet", false, "")
	got := reorder(fs, []string{"nightly", "--period", "1h", "--quiet"})
	if strings.Join(got, " ") != "--period 1h --quiet nightly" {
		t.Fatalf("reorder lost the slug: %v", got)
	}
	if err := fs.Parse(got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "nightly" {
		t.Errorf("args = %v, want [nightly]", fs.Args())
	}
}

func TestLifecycle(t *testing.T) {
	c := newCLI(t)
	if rc := c.run(t, "add", "nightly", "--period", "1h", "--grace", "5m", "--note", "rsnapshot"); rc != exitOK {
		t.Fatalf("add rc=%d, stderr=%s", rc, c.err.String())
	}
	if !strings.Contains(c.out.String(), "added nightly") {
		t.Errorf("unexpected add output: %s", c.out.String())
	}
	if rc := c.run(t, "beat", "nightly"); rc != exitOK {
		t.Fatalf("beat rc=%d, stderr=%s", rc, c.err.String())
	}
	if rc := c.run(t, "check", "--quiet", "nightly"); rc != exitOK {
		t.Errorf("a check that just reported should exit 0, got %d", rc)
	}

	// Let two hours pass on knell's clock and the contract flips.
	c.advance(2 * time.Hour)
	if rc := c.run(t, "check", "--quiet", "nightly"); rc != 1 {
		t.Errorf("a silent check must exit 1 for cron, got %d", rc)
	}
	if rc := c.run(t, "check", "nightly"); rc != 1 {
		t.Errorf("check without --quiet should also exit 1, got %d", rc)
	}
	if !strings.Contains(c.out.String(), "silent") {
		t.Errorf("the report should name the state: %s", c.out.String())
	}
}

func TestAddValidatesInput(t *testing.T) {
	c := newCLI(t)
	cases := [][]string{
		{"add", "nightly"},
		{"add", "nightly", "--period", "0"},
		{"add", "nightly", "--period", "-1h"},
		{"add", "nightly", "--period", "1s"},
		{"add", "nightly", "--period", "1h", "--grace", "-5m"},
		{"add", "Bad Slug", "--period", "1h"},
		{"add", "--period", "1h"},
		{"add", "one", "two", "--period", "1h"},
	}
	for _, args := range cases {
		if rc := c.run(t, args...); rc != exitError {
			t.Errorf("%v: rc=%d, want 2 (stderr=%s)", args, rc, c.err.String())
		}
	}
	if rc := c.run(t, "list"); rc != exitOK {
		t.Fatal(rc)
	}
	if strings.Contains(c.out.String(), "Bad") || strings.Contains(c.out.String(), "one") {
		t.Errorf("a rejected add still created a check: %s", c.out.String())
	}
}

func TestUnknownSlugIsNeverHealthy(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "real", "--period", "1h")
	if rc := c.run(t, "check", "--quiet", "ghost"); rc != exitError {
		t.Errorf("an unconfigured check is a knell error, not a green light: rc=%d", rc)
	}
	if rc := c.run(t, "check", "--quiet", "real", "ghost"); rc != exitError {
		t.Errorf("one bad name in a list must fail closed: rc=%d", rc)
	}
	if rc := c.run(t, "history", "ghost"); rc != exitError {
		t.Errorf("history of a ghost: rc=%d", rc)
	}
	if rc := c.run(t, "token", "ghost"); rc != exitError {
		t.Errorf("token of a ghost: rc=%d", rc)
	}
}

func TestStrictAndIgnore(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "loud", "--period", "10m", "--grace", "10m")
	c.run(t, "add", "quiet", "--period", "1h", "--grace", "10m")
	c.run(t, "beat", "loud")
	c.run(t, "beat", "quiet")

	// 15 minutes later: loud is past its period but inside its grace, quiet is
	// comfortably on schedule.
	c.advance(15 * time.Minute)
	if rc := c.run(t, "check", "--quiet"); rc != exitOK {
		t.Errorf("late inside grace should pass by default, rc=%d", rc)
	}
	if rc := c.run(t, "check", "--quiet", "--strict"); rc != 1 {
		t.Errorf("--strict should promote late to a failure, rc=%d", rc)
	}

	// 25 minutes: loud is past period+grace, quiet still has 60+10 to go.
	c.advance(25 * time.Minute)
	if rc := c.run(t, "check", "--quiet"); rc != 1 {
		t.Fatalf("a silent check must fail, rc=%d", rc)
	}
	if rc := c.run(t, "check", "--quiet", "--ignore", "loud"); rc != exitOK {
		t.Errorf("--ignore loud should pass (stderr=%s), rc=%d", c.err.String(), rc)
	}
	if rc := c.run(t, "check", "--quiet", "--ignore", "loud,quiet"); rc != exitError {
		t.Errorf("ignoring everything is not health, rc=%d, want 2", rc)
	}
	if rc := c.run(t, "check", "--quiet", "--ignore", "quiet"); rc != 1 {
		t.Errorf("ignoring the healthy one must still report loud, rc=%d", rc)
	}
}

func TestPauseSilencesAlerts(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "during-maint", "--period", "10m", "--grace", "1m")
	c.run(t, "beat", "during-maint")
	c.advance(time.Hour)
	if rc := c.run(t, "check", "--quiet", "during-maint"); rc != 1 {
		t.Fatalf("setup: expected silent, rc=%d", rc)
	}
	if rc := c.run(t, "pause", "during-maint", "--note", "disk swap"); rc != exitOK {
		t.Fatalf("pause rc=%d (%s)", rc, c.err.String())
	}
	if rc := c.run(t, "check", "--quiet", "during-maint"); rc != exitOK {
		t.Errorf("a paused check must not fail a pipeline, rc=%d", rc)
	}
	if rc := c.run(t, "status"); rc != exitOK {
		t.Errorf("status with only a paused check should be green, rc=%d", rc)
	}
	if !strings.Contains(c.out.String(), "paused") {
		t.Errorf("status should show the pause: %s", c.out.String())
	}
	if rc := c.run(t, "resume", "during-maint"); rc != exitOK {
		t.Fatal(rc)
	}
	if rc := c.run(t, "check", "--quiet", "during-maint"); rc != 1 {
		t.Errorf("resuming must restore the alert, rc=%d", rc)
	}
}

func TestVerifyDetectsATamperedBeacon(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	c.run(t, "beat", "nightly")

	if rc := c.run(t, "verify"); rc != exitOK {
		t.Fatalf("a clean database should verify, rc=%d (%s)", rc, c.out.String())
	}
	if !strings.Contains(c.out.String(), "every beacon is explained") {
		t.Errorf("verify output: %s", c.out.String())
	}

	// Someone with write access to the file can change a row; they cannot change
	// its signature without the key, so the mismatch is the evidence.
	tamper(t, c.db(t), strings.Repeat("deadbeef", 8))
	if rc := c.run(t, "verify"); rc != 1 {
		t.Errorf("a forged beacon must exit 1, rc=%d", rc)
	}
	if !strings.Contains(c.out.String(), "FORGED") {
		t.Errorf("verify should name forgery: %s", c.out.String())
	}
	if rc := c.run(t, "verify", "--json"); rc != 1 {
		t.Fatalf("json verify rc=%d", rc)
	}
	var doc struct {
		Forged int64 `json:"forged"`
	}
	if err := json.Unmarshal(c.out.Bytes(), &doc); err != nil {
		t.Fatalf("verify --json: %v (%s)", err, c.out.String())
	}
	if doc.Forged != 1 {
		t.Errorf("forged = %d, want 1", doc.Forged)
	}
}

// A rotation must not rewrite history: beacons signed with the previous key stay
// verifiable, so `knell verify` reports them as old-key rather than forged.
func TestRotationKeepsOldBeaconsVerifiable(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	c.run(t, "beat", "nightly")
	if rc := c.run(t, "rotate", "nightly"); rc != exitOK {
		t.Fatalf("rotate rc=%d (%s)", rc, c.err.String())
	}
	c.run(t, "beat", "nightly")
	if rc := c.run(t, "verify"); rc != exitOK {
		t.Fatalf("rotation alone must not look like forgery, rc=%d (%s)", rc, c.out.String())
	}
	if !strings.Contains(c.out.String(), "1 old-key") {
		t.Errorf("the old beacon should be accounted for by the previous key: %s", c.out.String())
	}
}

func TestTokenMasksTheSecret(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	secret := readFirstSecret(t, filepath.Join(c.dir, "keys.json"))

	if rc := c.run(t, "token", "nightly"); rc != exitOK {
		t.Fatalf("token rc=%d (%s)", rc, c.err.String())
	}
	out := c.out.String()
	if strings.Contains(out, secret) {
		t.Error("token printed the whole secret without --reveal")
	}
	if !strings.Contains(out, "*") {
		t.Errorf("token should show a masked secret: %s", out)
	}
	if rc := c.run(t, "token", "--reveal", "nightly"); rc != exitOK {
		t.Fatal(rc)
	}
	if !strings.Contains(c.out.String(), secret) {
		t.Error("--reveal should print the secret")
	}
	if rc := c.run(t, "token", "--json", "nightly"); rc != exitOK {
		t.Fatal(rc)
	}
	if strings.Contains(c.out.String(), secret) {
		t.Error("token --json leaked the secret")
	}
	if rc := c.run(t, "token"); rc != exitError {
		t.Error("token needs exactly one slug")
	}
}

func TestSignProducesAnAcceptedTriple(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	if rc := c.run(t, "sign", "nightly"); rc != exitOK {
		t.Fatalf("sign rc=%d (%s)", rc, c.err.String())
	}
	if !strings.Contains(c.out.String(), "Knell-Signature") {
		t.Errorf("sign should print a curl command: %s", c.out.String())
	}
	if rc := c.run(t, "sign", "--json", "nightly"); rc != exitOK {
		t.Fatal(rc)
	}
	var hdr map[string]string
	if err := json.Unmarshal(c.out.Bytes(), &hdr); err != nil {
		t.Fatalf("sign --json: %v", err)
	}
	if hdr["Knell-Nonce"] == "" || hdr["Knell-Timestamp"] == "" {
		t.Errorf("incomplete headers: %v", hdr)
	}
}

func TestWrapModePropagatesTheChildExitCode(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h", "--grace", "1m")
	marker := filepath.Join(c.dir, "ran")

	// A job wrapped by knell must keep its own exit code: cron decides on the
	// job's result, not on knell's.
	if rc := c.run(t, "beat", "nightly", "--on", "success", "--", "/bin/sh", "-c", "touch "+marker+"; exit 5"); rc != 5 {
		t.Errorf("wrapped failure: rc=%d, want 5", rc)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the wrapped command did not run: %v", err)
	}
	// --on success and a failing job means no beacon: the switch trips on silence.
	if n := countBeacons(t, c.db(t), "nightly"); n != 0 {
		t.Errorf("a failed job beat %d time(s), want 0", n)
	}

	if rc := c.run(t, "beat", "nightly", "--on", "failure", "--", "/bin/sh", "-c", "exit 7"); rc != 7 {
		t.Errorf("wrapped failure with --on failure: rc=%d, want 7", rc)
	}
	if n := countBeacons(t, c.db(t), "nightly"); n != 1 {
		t.Errorf("--on failure should have beaten once, got %d", n)
	}

	os.Remove(marker)
	if rc := c.run(t, "beat", "nightly", "--on", "success", "--", "/bin/sh", "-c", "touch "+marker); rc != exitOK {
		t.Errorf("wrapped success: rc=%d", rc)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the wrapped command did not run on the success path")
	}
	if n := countBeacons(t, c.db(t), "nightly"); n != 2 {
		t.Errorf("--on success should have beaten, beacons=%d, want 2", n)
	}

	if rc := c.run(t, "beat", "nightly", "--on", "nonsense", "--", "/bin/true"); rc != exitError {
		t.Error("an unknown --on value must be refused")
	}
	if rc := c.run(t, "beat"); rc != exitError {
		t.Error("beat without a slug must be refused")
	}

	// A wrapped job that succeeded while its check-in failed is a monitoring
	// problem, not a job failure: that is exit 2, which is neither 0 (all well)
	// nor 1 (your backup broke).
	if rc := c.run(t, "beat", "--url", "http://127.0.0.1:1", "--timeout", "2s",
		"nightly", "--", "/bin/true"); rc != exitError {
		t.Errorf("job ok + check-in failed should be exit 2, got %d (%s)", rc, c.err.String())
	}
	// Without a wrapped job, a failed check-in is simply this command failing.
	if rc := c.run(t, "beat", "--url", "http://127.0.0.1:1", "--timeout", "2s", "nightly"); rc != exitUnhealthy {
		t.Errorf("a bare failed check-in should be exit 1, got %d", rc)
	}
	// The child's own failure still dominates everything.
	if rc := c.run(t, "beat", "--url", "http://127.0.0.1:1", "--timeout", "2s",
		"nightly", "--", "/bin/sh", "-c", "exit 9"); rc != 9 {
		t.Errorf("the job's exit code must win, got %d", rc)
	}
}

// A job killed by a signal has no exit code. Go reports -1, and os.Exit(-1) would
// surface as 255 — outside the documented contract — so it is reported as 1.
func TestSignalDeathIsReportedInContract(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	if rc := c.run(t, "beat", "--quiet", "nightly", "--", "/bin/sh", "-c", "kill -9 $$"); rc != exitUnhealthy {
		t.Errorf("a signal-killed job should exit 1, got %d", rc)
	}
}

// --quiet silences knell, not the job: cron mails whatever the command printed,
// and dropping it would lose the only output of a failing backup.
func TestQuietDoesNotSwallowChildOutput(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	if rc := c.run(t, "beat", "--quiet", "nightly", "--", "/bin/echo", "CHILD_OUTPUT_VISIBLE"); rc != exitOK {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(c.out.String(), "CHILD_OUTPUT_VISIBLE") {
		t.Errorf("--quiet swallowed the wrapped command's stdout: %q", c.out.String())
	}
	if strings.Contains(c.out.String(), "recorded beacon") {
		t.Error("--quiet should still suppress knell's own chatter")
	}
}

func TestSecretNeverNeedsArgv(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	// The keyring is the default source; a stale KNELL_SECRET is a hard error
	// rather than a silent 401 later.
	t.Setenv("KNELL_SECRET", "not-hex-at-all")
	if rc := c.run(t, "beat", "--local", "nightly"); rc != exitError {
		t.Errorf("a malformed KNELL_SECRET should be refused, rc=%d (%s)", rc, c.err.String())
	}
	os.Unsetenv("KNELL_SECRET")

	keyFile := filepath.Join(c.dir, "key.txt")
	os.WriteFile(keyFile, []byte(readFirstSecret(t, filepath.Join(c.dir, "keys.json"))+"\n"), 0o600)
	if rc := c.run(t, "beat", "--local", "--secret-file", keyFile, "nightly"); rc != exitOK {
		t.Errorf("--secret-file rc=%d (%s)", rc, c.err.String())
	}
}

func TestReportCommandsAreMachineReadable(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h", "--note", "nightly rsnapshot")
	c.run(t, "beat", "nightly")

	for _, args := range [][]string{
		{"status", "--json"}, {"list", "--json"}, {"history", "nightly", "--json"},
		{"alerts", "--json"}, {"check", "--json"}, {"verify", "--json"}, {"version", "--json"},
	} {
		if rc := c.run(t, args...); rc > 1 {
			t.Fatalf("%v rc=%d (%s)", args, rc, c.err.String())
		}
		var v any
		if err := json.Unmarshal(c.out.Bytes(), &v); err != nil {
			t.Errorf("%v did not produce JSON: %v\n%s", args, err, c.out.String())
		}
	}

	if rc := c.run(t, "status"); rc != exitOK {
		t.Fatal(rc)
	}
	if !strings.Contains(c.out.String(), "nightly rsnapshot") {
		t.Errorf("status lost the note: %s", c.out.String())
	}
	if !strings.Contains(c.out.String(), "no silence") {
		t.Errorf("status should summarise: %s", c.out.String())
	}
}

func TestStatusJSONCarriesTheContract(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h", "--grace", "2m")
	c.run(t, "beat", "nightly", "--note", "ran on nas0")
	if rc := c.run(t, "status", "--json"); rc != exitOK {
		t.Fatal(rc)
	}
	var doc struct {
		Checks []struct {
			Slug          string `json:"slug"`
			State         string `json:"state"`
			PeriodSeconds int64  `json:"period_seconds"`
			GraceSeconds  int64  `json:"grace_seconds"`
			LastBeacon    struct {
				Note   string `json:"note"`
				Signed bool   `json:"signed"`
			} `json:"last_beacon"`
		} `json:"checks"`
		Store struct {
			Beacons int64 `json:"beacons"`
		} `json:"store"`
	}
	if err := json.Unmarshal(c.out.Bytes(), &doc); err != nil {
		t.Fatalf("status --json: %v\n%s", err, c.out.String())
	}
	if len(doc.Checks) != 1 || doc.Checks[0].Slug != "nightly" {
		t.Fatalf("checks = %+v", doc.Checks)
	}
	if doc.Checks[0].State != "ok" || doc.Checks[0].PeriodSeconds != 3600 || doc.Checks[0].GraceSeconds != 120 {
		t.Errorf("contract fields wrong: %+v", doc.Checks[0])
	}
	if doc.Checks[0].LastBeacon.Note != "ran on nas0" || !doc.Checks[0].LastBeacon.Signed {
		t.Errorf("last beacon: %+v", doc.Checks[0].LastBeacon)
	}
	if doc.Store.Beacons != 1 {
		t.Errorf("store counts: %+v", doc.Store)
	}
}

func TestRmIsDestructiveByDefault(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")

	// No terminal to ask on: refuse rather than delete.
	if rc := c.run(t, "rm", "nightly"); rc != exitError {
		t.Errorf("rm without confirmation should fail on a closed stdin, rc=%d", rc)
	}
	if rc := c.run(t, "list"); rc != exitOK || !strings.Contains(c.out.String(), "nightly") {
		t.Error("a refused rm deleted the check")
	}
	if rc := c.run(t, "rm", "--yes", "nightly"); rc != exitOK {
		t.Fatalf("rm --yes rc=%d (%s)", rc, c.err.String())
	}
	if rc := c.run(t, "list", "--json"); rc != exitOK {
		t.Fatal(rc)
	}
	if strings.Contains(c.out.String(), "nightly") {
		t.Error("the check survived")
	}
	if keysRemaining(t, filepath.Join(c.dir, "keys.json")) {
		t.Error("rm left the signing key behind")
	}
	if rc := c.run(t, "rm", "--yes", "nightly"); rc != exitError {
		t.Error("deleting twice should report not-found")
	}
}

func TestGCPrunesButKeepsEvidence(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h")
	for i := 0; i < 6; i++ {
		if rc := c.run(t, "beat", "nightly"); rc != exitOK {
			t.Fatalf("beat %d: rc=%d (%s)", i, rc, c.err.String())
		}
	}
	// The check is silent by now, so pruning must not erase the fact that it once
	// reported: without a kept beacon the report would flip to "never", which is a
	// different diagnosis and the wrong one.
	c.advance(3 * time.Hour)
	time.Sleep(20 * time.Millisecond)

	if rc := c.run(t, "gc", "--keep", "5", "--max-age", "1ns", "--alert-max-age", "1ns"); rc != exitOK {
		t.Fatalf("gc rc=%d (%s)", rc, c.err.String())
	}
	if !strings.Contains(c.out.String(), "deleted") {
		t.Errorf("gc output: %s", c.out.String())
	}
	if rc := c.run(t, "history", "nightly", "--json"); rc != exitOK {
		t.Fatal(rc)
	}
	var bs []map[string]any
	if err := json.Unmarshal(c.out.Bytes(), &bs); err != nil {
		t.Fatalf("history --json: %v", err)
	}
	if len(bs) != 5 {
		t.Errorf("%d beacons survived --keep 5 of 6, want 5", len(bs))
	}
	if rc := c.run(t, "check", "--quiet", "nightly"); rc != 1 {
		t.Errorf("a stale check should still be silent after pruning (rc 1), got %d", rc)
	}
	if rc := c.run(t, "status"); rc != 1 {
		t.Fatal(rc)
	}
	if strings.Contains(c.out.String(), "never") {
		t.Errorf("pruning turned a gone-quiet check into a never-reported one: %s", c.out.String())
	}
	if rc := c.run(t, "verify", "--json"); rc != exitOK {
		t.Errorf("gc must not break verification: rc=%d %s", rc, c.out.String())
	}
}

func TestInitAndVersionAndHelp(t *testing.T) {
	c := newCLI(t)
	if rc := c.run(t, "init"); rc != exitOK {
		t.Fatalf("init rc=%d (%s)", rc, c.err.String())
	}
	// init creates the database and the config file; the keyring appears with the
	// first key, which is the point of keeping secrets out of a backed-up file.
	if _, err := os.Stat(c.a.cfg.DBPath); err != nil {
		t.Errorf("init should create the database: %v", err)
	}
	if _, err := os.Stat(os.Getenv("KNELL_CONFIG")); err != nil {
		t.Errorf("init should write a config file: %v", err)
	}
	if rc := c.run(t, "init"); rc != exitOK {
		t.Errorf("init should be idempotent, rc=%d", rc)
	}
	if !strings.Contains(c.out.String(), "already present") {
		t.Errorf("second init should say so: %s", c.out.String())
	}
	if rc := c.run(t, "version"); rc != exitOK {
		t.Fatal(rc)
	}
	if !strings.Contains(c.out.String(), "knell") {
		t.Errorf("version output: %s", c.out.String())
	}
	if rc := c.run(t, "help", "beat"); rc != exitOK {
		t.Errorf("help beat rc=%d", rc)
	}
	if !strings.Contains(c.err.String(), "usage: knell beat") {
		t.Errorf("help should print the command's usage: %s", c.err.String())
	}
	if rc := c.run(t, "help", "nonsense"); rc != exitError {
		t.Error("help for an unknown command should fail")
	}
	if rc := c.run(t, "nonsense"); rc != exitError {
		t.Error("an unknown command should fail")
	}
	if rc := c.run(t); rc != exitOK {
		t.Error("no arguments should print usage and exit 0")
	}
}

// The URL knell prints into a crontab line has to be pasteable as-is. An earlier
// version stripped the slug from a full beat path and then appended it again, so
// the setup instructions produced a doubled path and a switch that never armed.
func TestBeatURLIsNotDoubled(t *testing.T) {
	cases := []struct{ base, slug, want string }{
		{"http://h:8482", "nightly", "http://h:8482/api/v1/beat/nightly"},
		{"http://h:8482/", "nightly", "http://h:8482/api/v1/beat/nightly"},
		{"http://h:8482/api/v1/beat", "nightly", "http://h:8482/api/v1/beat/nightly"},
		{"http://h:8482/api/v1/beat/nightly", "nightly", "http://h:8482/api/v1/beat/nightly"},
		{"https://knell.example", "ci-build", "https://knell.example/api/v1/beat/ci-build"},
	}
	for _, c := range cases {
		if got := beatURL(c.base, c.slug); got != c.want {
			t.Errorf("beatURL(%q, %q) = %q, want %q", c.base, c.slug, got, c.want)
		}
	}
}

func TestAddPrintsAWorkingRemoteSetupLine(t *testing.T) {
	c := newCLI(t)
	if rc := c.run(t, "add", "nightly", "--period", "1h"); rc != exitOK {
		t.Fatalf("add rc=%d (%s)", rc, c.err.String())
	}
	out := c.out.String()
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "remote host:") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("add should print a remote setup line:\n%s", out)
	}
	url := strings.TrimSpace(strings.SplitN(strings.SplitAfter(line, "--url ")[1], " nightly", 2)[0])
	if url != c.a.cfg.BaseURL && url != strings.TrimRight(c.a.cfg.BaseURL, "/") {
		t.Errorf("add printed --url %q, which is not the configured base %q", url, c.a.cfg.BaseURL)
	}
	if got := beatURL(url, "nightly"); !strings.HasSuffix(got, "/api/v1/beat/nightly") ||
		strings.Contains(got, "/beat/api/v1") {
		t.Errorf("the printed URL would deliver to %q", got)
	}
}

// status carries the verdict too, so `knell status || notify` works. Documented in
// docs/DESIGN.md: a script that only wants the report says `|| true`.
func TestStatusCarriesTheVerdict(t *testing.T) {
	c := newCLI(t)
	c.run(t, "add", "nightly", "--period", "1h", "--grace", "5m")
	c.run(t, "beat", "nightly")
	if rc := c.run(t, "status"); rc != exitOK {
		t.Errorf("status while healthy: rc=%d", rc)
	}
	c.advance(4 * time.Hour)
	if rc := c.run(t, "status"); rc != 1 {
		t.Errorf("status while silent: rc=%d, want 1", rc)
	}
	if rc := c.run(t, "status", "--json"); rc != 1 {
		t.Errorf("status --json while silent: rc=%d, want 1", rc)
	}
	var doc map[string]any
	if err := json.Unmarshal(c.out.Bytes(), &doc); err != nil {
		t.Fatalf("status --json must still print the report: %v", err)
	}
	if rc := c.run(t, "list"); rc != exitOK {
		t.Errorf("list is a report, not a verdict: rc=%d", rc)
	}
	if rc := c.run(t, "alerts"); rc != exitOK {
		t.Errorf("alerts should exit 0 after printing: rc=%d", rc)
	}
	if !strings.Contains(c.out.String(), "silent") {
		t.Errorf("the CLI should have recorded the transition without a daemon: %s", c.out.String())
	}
}

func TestCheckWithNoChecksConfigured(t *testing.T) {
	c := newCLI(t)
	// Nothing configured is not "all well": a wiped checks table must not look
	// green to the cron entry that depends on it.
	if rc := c.run(t, "check", "--quiet"); rc != exitError {
		t.Errorf("check with no checks: rc=%d, want 2", rc)
	}
	if rc := c.run(t, "check"); rc != exitError {
		t.Errorf("check (verbose) with no checks: rc=%d, want 2 (%s)", rc, c.out.String())
	}
	if !strings.Contains(c.err.String(), "nothing to check") {
		t.Errorf("the refusal should say why: %q", c.err.String())
	}
	if rc := c.run(t, "status"); rc != exitOK {
		t.Errorf("status is a report, not a verdict: rc=%d", rc)
	}
	if !strings.Contains(c.out.String(), "no checks configured") {
		t.Errorf("the empty case should say what to do next: %s", c.out.String())
	}
}

func tamper(t *testing.T, db *sql.DB, sig string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE beacons SET sig = ?1`, sig); err != nil {
		t.Fatal(err)
	}
}

func countBeacons(t *testing.T, db *sql.DB, slug string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM beacons WHERE slug = ?1`, slug).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func readFirstSecret(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading keyring: %v", err)
	}
	var doc struct {
		Keys map[string]struct {
			Secret string `json:"secret"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("keyring is not JSON: %v\n%s", err, b)
	}
	for _, k := range doc.Keys {
		if k.Secret != "" {
			return k.Secret
		}
	}
	t.Fatal("no secret in the keyring")
	return ""
}

func keysRemaining(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		t.Fatal(err)
	}
	return strings.Contains(string(b), "secret")
}
