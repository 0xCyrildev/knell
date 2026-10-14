package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xCyrildev/knell/internal/config"
	"github.com/0xCyrildev/knell/internal/report"
	"github.com/0xCyrildev/knell/internal/sanitize"
	"github.com/0xCyrildev/knell/internal/sign"
	"github.com/0xCyrildev/knell/internal/store"
)

// cmdAdd creates a check and its signing key together, because a check without
// a key can never be beaten.
func (a *app) cmdAdd(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("add")
	period := fs.Duration("period", 0, "how often a beacon is expected, e.g. 1h, 30m, 1h30m (required)")
	grace := fs.Duration("grace", 10*time.Minute, "extra slack before a miss becomes an alert")
	note := fs.String("note", "", "what this check is, for whoever reads `knell status` later")
	secret := fs.String("secret", "", "use this signing key instead of generating one (64 hex, or @file, or - for stdin)")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell add <slug> --period 1h [--grace 10m] [--note TEXT] [--secret …]

Creates a check and mints its signing key. The secret is printed once: it is what a
cron entry or agent uses to sign beacons, and knell stores only its fingerprint in the
database.

  knell add nightly-backup --period 24h --grace 2h --note 'rsnapshot to nas0'
`)
		fs.PrintDefaults()
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	defer a.close()
	slug := fs.Arg(0)
	if slug == "" || fs.NArg() != 1 {
		fmt.Fprintln(a.stderr, "knell add: exactly one slug is required")
		return exitError
	}
	if !sign.ValidSlug(slug) {
		return a.fail(fmt.Errorf("slug must match ^[a-z0-9][a-z0-9._-]{0,63}$, got %q", slug))
	}
	if *period <= 0 {
		return a.fail(errors.New("--period is required and must be positive (e.g. --period 1h)"))
	}
	if *grace < 0 {
		return a.fail(errors.New("--grace must not be negative"))
	}
	if *grace > *period {
		fmt.Fprintf(a.stderr, "knell: note: grace (%s) is longer than the period (%s); alerts will be slow\n",
			*grace, *period)
	}
	if *period < 10*time.Second {
		return a.fail(errors.New("--period must be at least 10s"))
	}
	key, err := readKeyFlag(*secret, a.stdin)
	if err != nil {
		return a.fail(err)
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	ctx := context.Background()
	if err := a.st.AddCheck(ctx, store.Spec{Slug: slug, Period: *period, Grace: *grace, Note: sanitize.Text(*note)}); err != nil {
		if errors.Is(err, store.ErrExists) {
			return a.fail(fmt.Errorf("check %q already exists (knell list)", slug))
		}
		return a.fail(err)
	}
	printed, err := a.keys.Put(slug, key)
	if err != nil {
		_ = a.st.DeleteCheck(ctx, slug)
		return a.fail(err)
	}
	kid := store.KeyID(printed)
	if err := a.st.UpdateCheck(ctx, slug, store.Patch{KeyID: &kid}); err != nil {
		a.log.Warn("recording key fingerprint", "err", err)
	}
	url := beatURL(a.serverBase(), slug)
	if *jsonOut {
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(map[string]any{
			"slug": slug, "period": period.String(), "grace": grace.String(),
			"key_id": kid, "secret": printed, "beat_url": url, "note": *note,
		}))
		return exitOK
	}
	fmt.Fprintf(a.stdout, "added %s: expect a beacon every %s, alert after %s of silence\n\n",
		slug, *period, *grace)
	fmt.Fprintf(a.stdout, "signing key (printed once, fingerprint %s):\n  %s\n\n", kid, printed)
	fmt.Fprintf(a.stdout, "local host:   knell beat %s\n", slug)
	fmt.Fprintf(a.stdout, "remote host:  KNELL_SECRET=%s knell beat --url %s %s\n", printed,
		a.serverBase(), slug)
	fmt.Fprintf(a.stdout, "beat path:    %s\n", url)
	fmt.Fprintf(a.stdout, "curl:         see: knell sign %s\n", slug)
	return exitOK
}

func (a *app) cmdRm(args []string) int {
	fs, _, _ := a.newFlagSet("rm")
	yes := fs.Bool("yes", false, "do not ask")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell rm [--yes] <slug>\n\nDeletes a check, its beacons, its alert history and its signing key. This is the one\nknell command that destroys recorded evidence, so it asks.\n")
		fs.PrintDefaults()
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	defer a.close()
	slug := fs.Arg(0)
	if slug == "" || fs.NArg() != 1 {
		fmt.Fprintln(a.stderr, "knell rm: exactly one slug is required")
		return exitError
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	ctx := context.Background()
	c, err := a.st.GetCheck(ctx, slug)
	if err != nil {
		return a.fail(err)
	}
	if !*yes {
		fmt.Fprintf(a.stderr, "delete %q (%d beacon(s) recorded)? [y/N] ", slug, c.BeaconCount)
		var answer string
		if _, err := fmt.Fscan(a.stdin, &answer); err != nil {
			return a.fail(errors.New("no terminal to confirm on; pass --yes"))
		}
		switch answer {
		case "y", "Y", "yes":
		default:
			fmt.Fprintln(a.stdout, "left alone")
			return exitOK
		}
	}
	if err := a.st.DeleteCheck(ctx, slug); err != nil {
		return a.fail(err)
	}
	if err := a.keys.Delete(slug); err != nil {
		a.log.Warn("deleting key", "err", err)
	}
	fmt.Fprintf(a.stdout, "deleted %s\n", slug)
	return exitOK
}

func (a *app) cmdPause(args []string) int { return a.setPaused(args, true) }
func (a *app) cmdResume(args []string) int {
	return a.setPaused(args, false)
}

func (a *app) setPaused(args []string, paused bool) int {
	name := "pause"
	if !paused {
		name = "resume"
	}
	fs, _, _ := a.newFlagSet(name)
	note := fs.String("note", "", "why (a maintenance window, a migration)")
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "usage: knell %s [--note TEXT] <slug> ...\n\nA paused check is reported as paused and never alerts; beacons are still recorded, so\nthe history is complete when it resumes.\n", name)
		fs.PrintDefaults()
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	defer a.close()
	if fs.NArg() == 0 {
		fmt.Fprintf(a.stderr, "knell %s: at least one slug is required\n", name)
		return exitError
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	ctx := context.Background()
	rc := exitOK
	for _, slug := range fs.Args() {
		p := store.Patch{Paused: &paused}
		if *note != "" {
			n := sanitize.Text(*note)
			p.Note = &n
		}
		if err := a.st.UpdateCheck(ctx, slug, p); err != nil {
			fmt.Fprintf(a.stderr, "knell %s: %v\n", name, err)
			rc = exitError
			continue
		}
		word := "resumed"
		if paused {
			word = "paused"
		}
		fmt.Fprintf(a.stdout, "%s: %s\n", slug, word)
	}
	return rc
}

func (a *app) cmdList(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("list")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell list [--json]\n\nShows configured checks, their schedules and the fingerprint of each key.\n")
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	defer a.close()
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	cs, err := a.st.ListChecks(context.Background())
	if err != nil {
		return a.fail(err)
	}
	if err := report.Checks(a.stdout, cs, a.keys.Fingerprints(), *jsonOut); err != nil {
		return a.fail(err)
	}
	return exitOK
}

func (a *app) cmdGC(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("gc")
	keep := fs.Int("keep", a.cfg.KeepBeacons, "newest beacons to keep per check no matter their age")
	maxAge := fs.Duration("max-age", a.cfg.BeaconMaxAge.Duration, "delete beacons older than this")
	alertAge := fs.Duration("alert-max-age", a.cfg.AlertMaxAge.Duration, "delete alerts older than this")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell gc [--keep N] [--max-age D] [--alert-max-age D]\n\nPrunes history so the database stops growing. `knell serve` runs this on a timer; this\ncommand is for a cron-scheduled prune or a one-off cleanup.\n")
		fs.PrintDefaults()
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	defer a.close()
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	if *keep <= 0 {
		return a.fail(errors.New("--keep must be at least 1: pruning every beacon would turn a gone-quiet check into \"never reported\""))
	}
	rep, err := a.st.GC(context.Background(), store.GCOptions{
		KeepPerCheck: *keep, MaxAge: *maxAge, AlertMaxAge: *alertAge,
	})
	if err != nil {
		return a.fail(err)
	}
	if *jsonOut {
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(rep))
		return exitOK
	}
	fmt.Fprintf(a.stdout, "deleted %d beacon(s) and %d alert(s)\n", rep.BeaconsDeleted, rep.AlertsDeleted)
	if rep.Warning != "" {
		fmt.Fprintln(a.stderr, "knell: warning:", rep.Warning)
	}
	return exitOK
}

// cmdInit creates the state directory, the database and a config file.
func (a *app) cmdInit(args []string) int {
	fs, _, _ := a.newFlagSet("init")
	force := fs.Bool("force", false, "overwrite an existing config file")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell init [--force]\n\nCreates the database, the keyring path and a config file. Idempotent.\n")
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	defer a.close()
	for _, dir := range []string{filepath.Dir(a.cfg.DBPath), filepath.Dir(a.cfg.KeysPath), filepath.Dir(configFile())} {
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return a.fail(err)
			}
		}
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	cf := configFile()
	if _, err := os.Stat(cf); err == nil && !*force {
		fmt.Fprintf(a.stdout, "config already present at %s (use --force to rewrite)\n", cf)
	} else if err := os.WriteFile(cf, []byte(sampleConfig(a.cfg)), 0o600); err != nil {
		return a.fail(err)
	} else {
		fmt.Fprintf(a.stdout, "wrote %s\n", cf)
	}
	fmt.Fprintf(a.stdout, "database: %s\nkeyring:  %s\n", a.cfg.DBPath, a.cfg.KeysPath)
	fmt.Fprintf(a.stdout, "\nnext: knell add my-job --period 1h, then  0 * * * * knell beat my-job\n")
	return exitOK
}

func configFile() string { return config.File() }

// sampleConfig writes the resolved paths in, so the file a reader gets is the
// file knell is actually using and not a template that can drift from it.
func sampleConfig(c config.Config) string {
	return fmt.Sprintf(`{
  "db_path": %q,
  "keys_path": %q,
  "listen": %q,
  "base_url": %q,
  "skew": %q,
  "eval_interval": %q,
  "gc_interval": %q,
  "keep_beacons_per_check": %d,
  "beacon_max_age": %q,
  "beacon_mode": %q,
  "notify_cmd": "",
  "log_format": %q,
  "log_level": %q
}
`, c.DBPath, c.KeysPath, c.Listen, c.BaseURL,
		c.Skew.String(), c.EvalEvery.String(), c.GCEvery.String(),
		c.KeepBeacons, c.BeaconMaxAge.String(), c.BeaconMode, c.LogFormat, c.LogLevel)
}

func (a *app) cmdHelp(arg string) int {
	fn, ok := map[string]func([]string) int{
		"add": a.cmdAdd, "alerts": a.cmdAlerts, "beat": a.cmdBeat, "check": a.cmdCheck,
		"gc": a.cmdGC, "history": a.cmdHistory, "init": a.cmdInit, "list": a.cmdList,
		"pause": a.cmdPause, "resume": a.cmdResume, "rm": a.cmdRm, "rotate": a.cmdRotate,
		"serve": a.cmdServe, "sign": a.cmdSign, "status": a.cmdStatus, "token": a.cmdToken,
		"verify": a.cmdVerify, "version": a.cmdVersion, "ping": a.cmdPing,
	}[arg]
	if !ok {
		fmt.Fprintf(a.stderr, "knell: no help for %q\n\n", arg)
		a.usage(a.stderr)
		return exitError
	}
	fn([]string{"-h"})
	return exitOK
}

// readKeyFlag accepts a literal key, @path or "-" for stdin. The @file form
// exists so a check can be created from a secret manager's output without the
// key ever appearing in a command line.
func readKeyFlag(v string, stdin io.Reader) (string, error) {
	switch {
	case v == "":
		return "", nil
	case v == "-":
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("reading key from stdin: %w", err)
		}
		return parseKey(firstLine(b))
	case strings.HasPrefix(v, "@"):
		b, err := os.ReadFile(v[1:])
		if err != nil {
			return "", fmt.Errorf("reading key file: %w", err)
		}
		return parseKey(firstLine(b))
	default:
		return parseKey(v)
	}
}

func parseKey(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if !sign.ValidSecret(s) {
		return "", fmt.Errorf("a signing key must be 64 lowercase hex characters, got %d characters", len(s))
	}
	return s, nil
}
