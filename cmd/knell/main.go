// Command knell is a dead man's switch for scheduled work: jobs check in with a
// signed beacon, and knell tells you which of them has gone quiet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/0xCyrildev/knell/internal/build"
	"github.com/0xCyrildev/knell/internal/config"
	"github.com/0xCyrildev/knell/internal/store"
)

// Exit codes are a documented contract; see docs/DESIGN.md.
const (
	exitOK        = 0
	exitUnhealthy = 1
	exitError     = 2
)

type app struct {
	cfg    config.Config
	log    *slog.Logger
	stdout io.Writer
	stderr io.Writer
	stdin  io.Reader

	st   *store.Store
	keys *store.Keys

	// clock is a field so a test can drive time; now() is the only way commands
	// read it, so a single report can never disagree with itself.
	clock func() time.Time
}

func (a *app) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}

func main() {
	a := &app{stdout: os.Stdout, stderr: os.Stderr, stdin: os.Stdin}
	os.Exit(a.run(os.Args[1:]))
}

func (a *app) run(argv []string) int {
	if len(argv) == 0 {
		a.usage(a.stdout)
		return exitOK
	}
	cmd, rest := argv[0], argv[1:]
	switch cmd {
	case "help", "-h", "--help":
		if len(rest) > 0 {
			return a.cmdHelp(rest[0])
		}
		a.usage(a.stdout)
		return exitOK
	case "version", "--version", "-v":
		return a.cmdVersion(rest)
	}

	if err := a.load(); err != nil {
		fmt.Fprintln(a.stderr, "knell:", err)
		return exitError
	}

	var dispatch = map[string]func([]string) int{
		"serve":   a.cmdServe,
		"init":    a.cmdInit,
		"add":     a.cmdAdd,
		"rm":      a.cmdRm,
		"pause":   a.cmdPause,
		"resume":  a.cmdResume,
		"list":    a.cmdList,
		"beat":    a.cmdBeat,
		"check":   a.cmdCheck,
		"status":  a.cmdStatus,
		"history": a.cmdHistory,
		"alerts":  a.cmdAlerts,
		"token":   a.cmdToken,
		"rotate":  a.cmdRotate,
		"sign":    a.cmdSign,
		"verify":  a.cmdVerify,
		"ping":    a.cmdPing,
		"gc":      a.cmdGC,
	}
	fn, ok := dispatch[cmd]
	if !ok {
		fmt.Fprintf(a.stderr, "knell: unknown command %q\n\n", cmd)
		a.usage(a.stderr)
		return exitError
	}
	return fn(rest)
}

// load reads config and prepares the local database and keyring. Commands that
// do not need the database never open it, so `knell sign` cannot fail on a locked
// file and `knell serve` does not create surprise directories in $HOME.
func (a *app) load() error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	a.cfg = cfg
	a.log = newLogger(cfg, a.stderr)
	return nil
}

// local opens the database and keyring.
func (a *app) local() error {
	if a.st != nil {
		return nil
	}
	st, err := store.Open(a.cfg.DBPath)
	if err != nil {
		return err
	}
	keys, err := store.OpenKeys(a.cfg.KeysPath)
	if err != nil {
		st.Close()
		return err
	}
	a.st, a.keys = st, keys
	return nil
}

func (a *app) close() {
	if a.st != nil {
		_ = a.st.Close()
		a.st = nil
	}
}

func newLogger(cfg config.Config, w io.Writer) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// withCancel returns a context that dies on SIGINT/SIGTERM, plus the signal
// channel stop so a command can tell "interrupted" from "finished".
func withCancel() (context.Context, func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, stop
}

func (a *app) usage(w io.Writer) {
	fmt.Fprintf(w, `knell — has my scheduled work gone quiet?

  knell add <slug> --period 1h            watch a job that should check in hourly
  knell beat <slug>                        check in (local database, or --url over HTTP)
  knell check --all                        exit 1 if anything is silent
  knell status                             what is alive, what is not, since when
  knell serve                              run the collector for remote beacons
  knell token <slug>                       the secret and a paste-ready cron line

State is a single SQLite file plus a 0600 keyring; no daemon is required to
record or check beacons locally.

Commands: %s

Exit codes: 0 all well · 1 something is silent · 2 knell could not decide
Run 'knell help <command>' for one command's flags.
`, strings.Join(sortedCommands, ", "))
}

var sortedCommands = []string{
	"add", "alerts", "beat", "check", "gc", "history", "init", "list",
	"pause", "ping", "resume", "rm", "rotate", "serve", "sign", "status", "token", "verify", "version",
}

func (a *app) cmdVersion(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	jsonOut := fs.Bool("json", false, "machine-readable")
	fs.Usage = func() { fmt.Fprint(a.stderr, "usage: knell version [--json]\n") }
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if *jsonOut {
		fmt.Fprintf(a.stdout, `{"version":%q,"commit":%q,"date":%q,"go":%q}`+"\n",
			build.Version, build.Commit, build.Date, runtime.Version())
		return exitOK
	}
	fmt.Fprintln(a.stdout, "knell "+build.String())
	return exitOK
}

// newFlagSet builds a flag set for a reporting command: the shared state flags
// plus output control. Commands that produce no report use baseFlagSet directly,
// so `knell serve --help` never advertises a --json flag it ignores.
func (a *app) newFlagSet(name string) (*flag.FlagSet, *bool, *bool) {
	fs := a.baseFlagSet(name)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	quiet := fs.Bool("quiet", false, "print nothing; communicate by exit code")
	return fs, jsonOut, quiet
}

// applyStateFlags folds the shared flags back into the config, after the caller
// has parsed. Keeping this in one place is what makes flag > env > file true for
// every subcommand.
func (a *app) applyStateFlags(fs *flag.FlagSet) error {
	if v := fs.Lookup("db"); v != nil && isSet(fs, "db") {
		a.cfg.DBPath = v.Value.String()
	}
	if v := fs.Lookup("keys"); v != nil && isSet(fs, "keys") {
		a.cfg.KeysPath = v.Value.String()
	}
	if v := fs.Lookup("log-level"); v != nil && isSet(fs, "log-level") {
		a.cfg.LogLevel = v.Value.String()
		a.log = newLogger(a.cfg, a.stderr)
	}
	if err := a.cfg.Validate(); err != nil {
		return err
	}
	abs, err := filepath.Abs(a.cfg.DBPath)
	if err == nil {
		a.cfg.DBPath = abs
	}
	return nil
}

func isSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// parse accepts flags in any position, which is what people type:
// `knell add nightly --period 1h` and `knell add --period 1h nightly` must mean
// the same thing. Go's flag package stops at the first positional argument, so
// argv is reordered against the command's own flag definitions before parsing.
func (a *app) parse(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorder(fs, args))
}

func reorder(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); {
		arg := args[i]
		switch {
		case arg == "--":
			// A terminator and everything after it is verbatim: knell's own
			// flags have no claim on a wrapped command's argv. Positionals seen
			// so far still belong before it, or the slug would be lost.
			out := append(append([]string{}, flags...), positional...)
			return append(out, args[i:]...)
		case len(arg) > 1 && arg[0] == '-':
			name := strings.TrimLeft(arg, "-")
			flags = append(flags, arg)
			i++
			if name == "" || name == "h" || name == "help" || strings.Contains(name, "=") {
				continue
			}
			f := fs.Lookup(name)
			if f != nil && !isBoolFlag(f) && i < len(args) {
				flags = append(flags, args[i])
				i++
			}
		default:
			positional = append(positional, arg)
			i++
		}
	}
	return append(flags, positional...)
}

func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

func (a *app) fail(err error) int {
	if err != nil {
		fmt.Fprintln(a.stderr, "knell:", err)
		return exitError
	}
	return exitOK
}

var errUsage = errors.New("usage error")
