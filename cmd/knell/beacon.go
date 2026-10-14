package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/0xCyrildev/knell/internal/client"
	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/sign"
	"github.com/0xCyrildev/knell/internal/store"
)

// cmdBeat checks in on behalf of a job. Two things make it safe to put in a
// crontab: it never needs the secret on the command line, and when it wraps the
// job itself it returns the job's exit code, not knell's.
func (a *app) cmdBeat(args []string) int {
	fs, _, quiet := a.newFlagSet("beat")
	url := fs.String("url", "", "deliver to this base URL or full beat URL instead of recording locally")
	local := fs.Bool("local", false, "record into the local database even when a server is configured")
	secretFlag := fs.String("secret", "", "signing key; prefer KNELL_SECRET or --secret-file (argv is visible in ps)")
	secretFile := fs.String("secret-file", "", "read the signing key from this file, or - for stdin")
	note := fs.String("note", "", "short note recorded with the beacon")
	on := fs.String("on", "always", "with '-- <command>': beat on success, failure or always")
	timeout := fs.Duration("timeout", 20*time.Second, "budget for delivery, including retries")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell beat [flags] <slug> [-- <command> ...]

  knell beat nightly                              record a beacon in the local database
  knell beat --url http://knell.example nightly   deliver it to a remote collector
  knell beat --on failure -- ./backup.sh          check in only when the job fails
  KNELL_SECRET=… knell beat --url … nightly       sign without putting the key in argv

flags must come before <slug>. A wrapped command keeps its own exit code, which is the
point: cron must act on the job, not on knell.

Exit codes
  0  the check-in landed (or, with --, the wrapped command succeeded and checked in)
  1  this command could not check in
  2  knell itself is the problem: bad flags, no key, a refused signature — or a
     wrapped command that succeeded while its check-in did not
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

	slug, child := splitArgs(fs.Args())
	if slug == "" {
		fmt.Fprintln(a.stderr, "knell beat: a slug is required (knell beat <slug>)")
		return exitError
	}
	mode := *on
	switch mode {
	case "always", "success", "failure":
	default:
		fmt.Fprintf(a.stderr, "knell beat: --on must be always, success or failure, got %q\n", mode)
		return exitError
	}

	childCode := 0
	hadChild := len(child) > 0
	if hadChild {
		childCode = a.runChild(child)
		shouldBeat := mode == "always" || (mode == "success" && childCode == 0) || (mode == "failure" && childCode != 0)
		if !shouldBeat {
			return childCode
		}
		noteText := *note
		if noteText == "" {
			noteText = fmt.Sprintf("command exit %d", childCode)
		}
		*note = noteText
	}

	push, base := a.shouldPush(*url, *local)
	if !push {
		if err := a.local(); err != nil {
			return a.fail(err)
		}
		if _, err := a.st.GetCheck(context.Background(), slug); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				fmt.Fprintf(a.stderr, "knell beat: no check %q — create it with: knell add %s --period 1h\n", slug, slug)
				return exitError
			}
			return a.fail(err)
		}
	} else {
		// A beacon delivered to a remote collector does not need a local database:
		// an agent box holds a secret and a URL, nothing else. Opening the keyring
		// anyway is what lets the same host sign from its own keyring, so a failure
		// here is only fatal if no secret turns up below.
		_ = a.local()
	}

	secret, src, err := a.resolveSecret(slug, *secretFlag, *secretFile, push)
	if err != nil {
		fmt.Fprintln(a.stderr, "knell beat:", err)
		return exitError
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if !push {
		b, err := a.record(slug, secret, *note)
		if err != nil {
			fmt.Fprintln(a.stderr, "knell beat:", err)
			return beatFailureRC(childCode, hadChild)
		}
		if !*quiet {
			fmt.Fprintf(a.stdout, "recorded beacon for %s at %s (%s)\n", slug,
				time.Unix(b.ReceivedAt, 0).Local().Format(time.RFC3339), src)
		}
		return childCode
	}

	target := client.Target{
		URL: beatURL(base, slug), Slug: slug, Secret: secret, Note: *note,
		Timeout: *timeout, Retries: 3,
	}
	res, err := target.Beat(ctx)
	if err != nil {
		fmt.Fprintln(a.stderr, "knell beat:", err)
		if res != nil && res.Status >= 400 && res.Status < 500 && !hadChild {
			// A refusal is a verdict about this beacon, not a retryable stumble.
			return exitError
		}
		return beatFailureRC(childCode, hadChild)
	}
	if !*quiet {
		fmt.Fprintf(a.stdout, "beacon accepted for %s (state %s)\n", slug, orUnknown(res.State))
	}
	return childCode
}

// shouldPush decides between recording and delivering: an explicit --url always
// delivers, --local always records, and otherwise the configured beacon_mode
// (or a set KNELL_URL) decides. Explicit flags win over config, which beats
// defaults, so a crontab line can be trusted to do the same thing forever.
func (a *app) shouldPush(urlFlag string, local bool) (bool, string) {
	if local {
		return false, ""
	}
	if urlFlag != "" {
		return true, strings.TrimRight(urlFlag, "/")
	}
	if os.Getenv("KNELL_URL") != "" {
		return true, strings.TrimRight(a.cfg.BaseURL, "/")
	}
	if a.cfg.BeaconMode == "push" {
		return true, strings.TrimRight(a.cfg.BaseURL, "/")
	}
	return false, ""
}

// beatURL accepts either a base URL or a full beat path. The suffix tests are
// explicit rather than substring-sniffing, because the line knell prints in
// `knell add` output has to be pasteable into a crontab exactly as it stands —
// and a doubled path would make a dead man's switch that never arms.
func beatURL(base, slug string) string {
	b := strings.TrimRight(base, "/")
	switch {
	case strings.HasSuffix(b, "/api/v1/beat/"+slug):
		return b
	case strings.HasSuffix(b, "/api/v1/beat"):
		return b + "/" + slug
	default:
		return b + "/api/v1/beat/" + slug
	}
}

// serverBase is what knell tells an operator to paste: the collector's base URL,
// never the beat path, because `knell beat --url` takes a base.
func (a *app) serverBase() string { return strings.TrimRight(a.cfg.BaseURL, "/") }

// resolveSecret finds the signing key without ever requiring it in argv. With a
// known source it can also tell the operator where the key came from, which is
// the difference between a wrong key and a wrong check.
func (a *app) resolveSecret(slug, flagSecret, flagFile string, push bool) (string, string, error) {
	if flagFile != "" {
		var (
			b   []byte
			err error
		)
		if flagFile == "-" {
			b, err = io.ReadAll(a.stdin)
		} else {
			b, err = os.ReadFile(flagFile)
		}
		if err != nil {
			return "", "", fmt.Errorf("reading secret: %w", err)
		}
		s := firstLine(b)
		if !sign.ValidSecret(s) {
			return "", "", fmt.Errorf("%s does not contain a 64-character hex key", flagFile)
		}
		return s, "file", nil
	}
	if flagSecret != "" {
		fmt.Fprintln(a.stderr, "knell: warning: a key in argv is readable by any local user via ps")
		if !sign.ValidSecret(flagSecret) {
			return "", "", fmt.Errorf("--secret must be 64 hexadecimal characters")
		}
		return flagSecret, "--secret", nil
	}
	if s := firstLine([]byte(os.Getenv("KNELL_SECRET"))); s != "" {
		if !sign.ValidSecret(s) {
			return "", "", fmt.Errorf("KNELL_SECRET must be 64 hexadecimal characters")
		}
		return s, "KNELL_SECRET", nil
	}
	if a.keys != nil {
		s, err := a.keys.Get(slug)
		switch {
		case err == nil:
			return s, a.cfg.KeysPath, nil
		case errors.Is(err, store.ErrNoKey) && !push:
			// Local recording is authoritative on its own host: whoever can edit
			// the file can already write any row, so a signature would add
			// bookkeeping rather than protection.
			return "", "unsigned (no key for this check)", nil
		default:
			return "", "", fmt.Errorf("%w — a beacon delivered over the network must be signed", err)
		}
	}
	return "", "", fmt.Errorf("no signing key for %q: pass --secret-file, set KNELL_SECRET, or read it from %s (knell token %s)",
		slug, a.cfg.KeysPath, slug)
}

func (a *app) record(slug, secret, note string) (health.Beacon, error) {
	now := time.Now()
	nonce, err := sign.NewNonce()
	if err != nil {
		return health.Beacon{}, err
	}
	b := health.Beacon{Slug: slug, TS: now.Unix(), ReceivedAt: now.Unix(), Source: "local", Nonce: nonce, Note: note}
	if secret != "" {
		sig, err := sign.Signature(secret, slug, b.TS, nonce)
		if err != nil {
			return health.Beacon{}, err
		}
		b.Sig = sig
	}
	if err := a.st.RecordBeacon(context.Background(), b); err != nil {
		return health.Beacon{}, err
	}
	return b, nil
}

// runChild executes the wrapped command with knell's stdio and returns its exit
// code, so `knell beat -- <job>` cannot mask a failing job from cron.
func (a *app) runChild(argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = a.stdin
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code := ee.ExitCode()
			if code < 0 {
				// Killed by a signal. Go reports -1, and os.Exit(-1) surfaces as
				// 255 — outside the documented contract — so it is reported as an
				// unhealthy result instead.
				fmt.Fprintf(a.stderr, "knell: %s was killed by a signal\n", argv[0])
				return exitUnhealthy
			}
			return code
		}
		fmt.Fprintf(a.stderr, "knell: cannot run %s: %v\n", argv[0], err)
		return exitError
	}
	return 0
}

// beatFailureRC decides what a failed check-in means when a job was wrapped.
//
// Without a child, 1 is what a user expects from a command that did not work.
// With one, the job's own code dominates — except when the job succeeded and the
// check-in did not: that is "the job is fine, the monitoring is not", which is
// exit 2 and is not the same message as "your backup failed".
func beatFailureRC(childCode int, hadChild bool) int {
	if !hadChild {
		return exitUnhealthy
	}
	if childCode != 0 {
		return childCode
	}
	return exitError
}

func splitArgs(args []string) (slug string, child []string) {
	for i, s := range args {
		if s == "--" {
			if i > 0 {
				slug = args[0]
			}
			return slug, args[i+1:]
		}
	}
	if len(args) > 0 {
		return args[0], nil
	}
	return "", nil
}

func firstLine(b []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			return t
		}
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// cmdToken prints how to check in: the URL, the key fingerprint, and the secret
// only when asked for it.
func (a *app) cmdToken(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("token")
	reveal := fs.Bool("reveal", false, "print the secret itself (it is otherwise masked)")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell token [--reveal|--json] <slug>

Prints the beat URL and signing key location for a check. The secret is masked by
default because this command is usually run in a terminal whose scrollback, or
whose tool output, is not secret storage.
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
		fmt.Fprintln(a.stderr, "knell token: exactly one slug is required")
		return exitError
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	ctx := context.Background()
	if _, err := a.st.GetCheck(ctx, slug); err != nil {
		return a.fail(fmt.Errorf("no check %q (knell add %s --period 1h)", slug, slug))
	}
	secret, err := a.keys.Get(slug)
	if err != nil {
		return a.fail(err)
	}
	url := strings.TrimRight(a.cfg.BaseURL, "/") + "/api/v1/beat/" + slug
	if *jsonOut {
		out := map[string]any{"slug": slug, "beat_url": url, "key_id": store.KeyID(secret), "keys_path": a.cfg.KeysPath}
		if *reveal {
			out["secret"] = secret
		}
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(out))
		return exitOK
	}
	fmt.Fprintf(a.stdout, "slug:        %s\nbeat url:    %s\nkey id:      %s\nkeys file:   %s\nsecret:      %s\n",
		slug, url, store.KeyID(secret), a.cfg.KeysPath, mask(secret, *reveal))
	if !*reveal {
		fmt.Fprintln(a.stdout, "\n(re-run with --reveal to print the secret; it is also in the keys file)")
		return exitOK
	}
	fmt.Fprintf(a.stdout, `
cron entry that delivers this beacon (the key comes from the environment, not argv):

  0 * * * * KNELL_SECRET=%s knell beat --url %s %s --quiet
`, secret, a.serverBase(), slug)
	return exitOK
}

// cmdSign emits ready-to-use signing headers, which is how you prove a beacon
// would be accepted without routing a request through the CLI's HTTP stack.
func (a *app) cmdSign(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("sign")
	secretFlag := fs.String("secret", "", "signing key")
	secretFile := fs.String("secret-file", "", "read the signing key from this file, or - for stdin")
	url := fs.String("url", "", "beat URL to curl")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell sign [--json] [--url URL] <slug>\n\nPrints a fresh Knell-Timestamp/Nonce/Signature triple for one beacon.\nA signature is only good inside the server's skew window, so generate it at send time.\n")
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
		fmt.Fprintln(a.stderr, "knell sign: exactly one slug is required")
		return exitError
	}
	// The keyring is only one possible source: an agent box that signs beacons has
	// a secret in its environment and no local state at all.
	_ = a.local()
	secret, _, err := a.resolveSecret(slug, *secretFlag, *secretFile, true)
	if err != nil {
		fmt.Fprintln(a.stderr, "knell sign:", err)
		return exitError
	}
	nonce, err := sign.NewNonce()
	if err != nil {
		return a.fail(err)
	}
	now := time.Now()
	h, err := client.Headers(secret, slug, now, nonce)
	if err != nil {
		return a.fail(err)
	}
	if *jsonOut {
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(h))
		return exitOK
	}
	target := *url
	if target == "" {
		target = strings.TrimRight(a.cfg.BaseURL, "/") + "/api/v1/beat/" + slug
	}
	fmt.Fprintf(a.stdout, `curl -sS -X POST %s \
  -H 'Knell-Timestamp: %s' \
  -H 'Knell-Nonce: %s' \
  -H 'Knell-Signature: %s'
`, target, h[client.HeaderTimestamp], h[client.HeaderNonce], h[client.HeaderSignature])
	return exitOK
}

// cmdRotate replaces a signing key, printing the new one once.
func (a *app) cmdRotate(args []string) int {
	fs, _, _ := a.newFlagSet("rotate")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell rotate <slug>\n\nMints a new signing key. The previous key is kept so old beacons stay verifiable.\n")
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
		fmt.Fprintln(a.stderr, "knell rotate: exactly one slug is required")
		return exitError
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	ctx := context.Background()
	if _, err := a.st.GetCheck(ctx, slug); err != nil {
		return a.fail(fmt.Errorf("no check %q", slug))
	}
	secret, err := a.keys.Put(slug, "")
	if err != nil {
		return a.fail(err)
	}
	kid := store.KeyID(secret)
	if err := a.st.UpdateCheck(ctx, slug, store.Patch{KeyID: &kid}); err != nil {
		a.log.Warn("recording key fingerprint", "err", err)
	}
	fmt.Fprintf(a.stdout, "rotated key for %s: %s\nnew secret (shown once): %s\n", slug, kid, secret)
	fmt.Fprintln(a.stdout, "update wherever the old key was used: systemd credentials, $KNELL_SECRET, the CI secret")
	return exitOK
}

// cmdVerify recomputes every stored beacon's signature. This is the payoff of
// signing: a database copy can be audited for invented check-ins, and a row that
// does not verify was either written by hand or signed with a key no longer held.
func (a *app) cmdVerify(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("verify")
	limit := fs.Int64("limit", 1000, "beacons to check per")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell verify [--limit N] [slug ...]

Re-computes the HMAC of every stored beacon. A mismatch means the row was not
produced by a holder of any key this knell has ever used for that check: either
someone edited the database, or the check's history predates a key that was
deleted.
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
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	ctx := context.Background()
	slugs := fs.Args()
	if len(slugs) == 0 {
		var err error
		if slugs, err = a.st.Slugs(ctx); err != nil {
			return a.fail(err)
		}
	}
	type row struct {
		Slug    string `json:"slug"`
		Total   int64  `json:"beacons"`
		Good    int64  `json:"verified"`
		Rotated int64  `json:"verified_old_key"`
		Unsig   int64  `json:"unsigned"`
		Bad     int64  `json:"forged"`
	}
	rows := []row{}
	for _, slug := range slugs {
		if !sign.ValidSlug(slug) {
			return a.fail(fmt.Errorf("invalid slug %q", slug))
		}
		bs, err := a.st.RecentBeacons(ctx, slug, int(*limit))
		if err != nil {
			return a.fail(err)
		}
		keys := a.keys.History(slug)
		r := row{Slug: slug, Total: int64(len(bs))}
		for _, b := range bs {
			switch {
			case b.Sig == "":
				r.Unsig++
			default:
				matched := false
				for _, k := range keys {
					want, err := sign.Signature(k, b.Slug, b.TS, b.Nonce)
					if err == nil && want == b.Sig {
						matched = true
						if k == keys[0] {
							r.Good++
						} else {
							r.Rotated++
						}
						break
					}
				}
				if !matched {
					r.Bad++
				}
			}
		}
		rows = append(rows, r)
	}
	bad := int64(0)
	for _, r := range rows {
		bad += r.Bad
	}
	if *jsonOut {
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(map[string]any{"checks": rows, "forged": bad}))
	} else {
		for _, r := range rows {
			fmt.Fprintf(a.stdout, "%-24s %5d beacons  %4d verified  %4d old-key  %4d unsigned  %4d FORGED\n",
				r.Slug, r.Total, r.Good, r.Rotated, r.Unsig, r.Bad)
		}
		if bad == 0 {
			fmt.Fprintf(a.stdout, "\nevery beacon is explained by a key this knell holds\n")
		} else {
			fmt.Fprintf(a.stdout, "\n%d beacon(s) cannot be explained by any known key\n", bad)
		}
	}
	if bad > 0 {
		return 1
	}
	return exitOK
}

func mask(secret string, reveal bool) string {
	if reveal {
		return secret
	}
	if len(secret) <= 12 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:6] + strings.Repeat("*", len(secret)-10) + secret[len(secret)-4:]
}
