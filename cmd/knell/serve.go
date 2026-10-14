package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/0xCyrildev/knell/internal/config"
	"github.com/0xCyrildev/knell/internal/server"
)

// cmdServe runs the collector that remote machines push beacons to. Local-only
// use does not need it: `knell beat` writes the same database directly.
func (a *app) cmdServe(args []string) int {
	fs := a.baseFlagSet("serve")
	addr := fs.String("addr", a.cfg.Listen, "host:port to bind ($KNELL_LISTEN); loopback by default")
	skew := fs.Duration("skew", a.cfg.Skew.Duration, "how far a beacon's timestamp may drift from the server clock")
	interval := fs.Duration("interval", a.cfg.EvalEvery.Duration, "how often to sweep for silence")
	gcEvery := fs.Duration("gc-interval", a.cfg.GCEvery.Duration, "how often to prune history (0 disables)")
	notify := fs.String("notify-cmd", a.cfg.NotifyCmd, "shell command run on a state change; details arrive in $KNELL_ALERT, $KNELL_SLUG, $KNELL_DETAIL")
	rate := fs.Float64("rate", a.cfg.RatePerSec, "accepted beacons per second per source address")
	logFormat := fs.String("log-format", a.cfg.LogFormat, "text or json")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell serve [flags]

Runs the HTTP collector:
  POST /api/v1/beat/<slug>    signed beacon (Knell-Timestamp, Knell-Nonce, Knell-Signature)
  GET  /healthz               liveness of this server, unauthenticated
  GET  /metrics               counters and gauges in Prometheus text format
  GET  /api/v1/status         verdicts, requires the admin bearer token
  GET  /api/v1/checks         configuration, requires the admin bearer token
  POST /api/v1/checks         create a check and return its new secret once
  DELETE /api/v1/checks/<slug> remove a check with its history

The admin API stays disabled unless KNELL_ADMIN_TOKEN is set in the environment.
TLS belongs to a reverse proxy or a sidecar; bind to loopback and terminate there.
`)
		fs.PrintDefaults()
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if isSet(fs, "log-format") {
		a.cfg.LogFormat = *logFormat
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}
	a.cfg.Listen = *addr
	a.cfg.Skew = config.Dur{Duration: *skew}
	a.cfg.EvalEvery = config.Dur{Duration: *interval}
	a.cfg.GCEvery = config.Dur{Duration: *gcEvery}
	a.cfg.NotifyCmd = *notify
	a.cfg.RatePerSec = *rate
	if err := a.cfg.Validate(); err != nil {
		return a.fail(err)
	}

	if *skew > 24*time.Hour {
		return a.fail(fmt.Errorf("skew %s would keep a captured beacon reusable for a day", *skew))
	}
	if *interval < time.Second {
		return a.fail(errors.New("--interval must be at least 1s"))
	}
	if publicBind(a.cfg.Listen) && a.cfg.AdminToken == "" {
		fmt.Fprintln(a.stderr, "knell: WARNING: bound to a routable address with no KNELL_ADMIN_TOKEN;")
		fmt.Fprintln(a.stderr, "knell: the beacon endpoint is still signed, but the admin API stays disabled.")
	}

	if err := a.local(); err != nil {
		return a.fail(err)
	}
	defer a.close()
	if _, err := os.Stat(a.cfg.KeysPath); err != nil {
		a.log.Info("keyring not created yet; it appears on the first `knell add`", "path", a.cfg.KeysPath)
	}
	srv := server.New(a.cfg, a.st, a.keys, a.log)
	srv.SetClock(a.now)
	ctx, stop := withCancel()
	defer stop()
	start := time.Now()
	if err := srv.Run(ctx); err != nil {
		a.log.Error("serving", "err", err)
		return exitError
	}
	a.log.Info("uptime", "seconds", int(time.Since(start).Seconds()))
	return exitOK
}

// baseFlagSet is the shared state flags without the output flags that only make
// sense for a report, so `knell serve --help` does not advertise --json.
func (a *app) baseFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.String("db", a.cfg.DBPath, "path to the SQLite state file ($KNELL_DB)")
	fs.String("keys", a.cfg.KeysPath, "path to the signing keyring ($KNELL_KEYS)")
	fs.String("log-level", a.cfg.LogLevel, "debug, info, warn or error")
	return fs
}

func publicBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "", "0.0.0.0", "::", "*":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	return host != "localhost" && !strings.HasSuffix(host, ".local")
}
