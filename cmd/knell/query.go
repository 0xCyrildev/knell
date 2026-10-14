package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/0xCyrildev/knell/internal/alert"
	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/report"
	"github.com/0xCyrildev/knell/internal/store"
)

// stringList is a repeatable flag: --ignore jobs --ignore staging.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

// cmdCheck is the command cron and CI call: it decides and says nothing unless
// asked.
func (a *app) cmdCheck(args []string) int {
	fs, jsonOut, quiet := a.newFlagSet("check")
	all := fs.Bool("all", false, "check every configured check (the default when no slug is given)")
	strict := fs.Bool("strict", false, "treat late (past the period, inside the grace) as a failure too")
	ignore := stringList{}
	fs.Var(&ignore, "ignore", "slug(s) to skip, repeatable or comma-separated")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell check [--all] [--strict] [--ignore slug]... [slug ...]

Exit codes are the point:
  0  every named check is inside its grace window
  1  at least one is silent (past period+grace, or never reported)
  2  knell could not decide: bad flags, unreadable state, or a slug that is not
     configured — an unknown name is never treated as healthy

  */5 * * * * knell check backups --quiet || logger "backups went quiet"
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
	now := a.now()

	a.quietLogs(*quiet)
	skipped := map[string]bool{}
	for _, s := range ignore {
		skipped[s] = true
	}

	names := fs.Args()
	if len(names) == 0 {
		*all = true
	}

	vs := []health.Verdict{}
	if *all {
		cs, err := a.st.ListChecks(ctx)
		if err != nil {
			return a.fail(err)
		}
		for _, c := range cs {
			if skipped[c.Slug] {
				continue
			}
			vs = append(vs, health.Evaluate(c, now))
		}
	} else {
		for _, slug := range names {
			if skipped[slug] {
				continue
			}
			c, err := a.st.GetCheck(ctx, slug)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					fmt.Fprintf(a.stderr, "knell check: no check %q — refusing to call it healthy\n", slug)
					return exitError
				}
				return a.fail(err)
			}
			vs = append(vs, health.Evaluate(c, now))
		}
	}
	health.Rank(vs)

	// Recording transitions here is what makes `knell alerts` answer "was it down
	// last Tuesday" in a deployment that runs no daemon. Hooks are disabled:
	// looking at the state must not page anyone.
	ev := alert.New(a.st, a.log, a.cfg.NotifyCmd).WithoutHooks()
	ev.Eval(ctx, now, vs)

	if len(vs) == 0 {
		// Nothing configured, or --ignore matched everything: knell cannot say
		// "all well" about a set it is not looking at, and a wiped checks table is
		// exactly the failure a monitoring tool must not report as green.
		if !*quiet {
			fmt.Fprintln(a.stderr, "knell check: nothing to check — no checks are configured, or --ignore matched them all")
		}
		return exitError
	}

	rc := health.Aggregate(vs, *strict)

	if *quiet {
		return rc
	}
	if err := report.Status(a.stdout, vs, now, *jsonOut); err != nil {
		return a.fail(err)
	}
	return rc
}

func (a *app) cmdStatus(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("status")
	alerts := fs.Int("alerts", 8, "how many recent state changes to show")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell status [--json] [--alerts N]\n\nEverything at once: each check's state, and the alert trail that explains it.\n")
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
	now := a.now()
	cs, err := a.st.ListChecks(ctx)
	if err != nil {
		return a.fail(err)
	}
	vs := make([]health.Verdict, 0, len(cs))
	for _, c := range cs {
		vs = append(vs, health.Evaluate(c, now))
	}
	health.Rank(vs)
	alert.New(a.st, a.log, a.cfg.NotifyCmd).WithoutHooks().Eval(ctx, now, vs)
	as, err := a.st.RecentAlerts(ctx, *alerts)
	if err != nil {
		return a.fail(err)
	}
	counts, err := a.st.Counts(ctx)
	if err != nil {
		return a.fail(err)
	}
	if *jsonOut {
		out := map[string]any{
			"time":   now,
			"checks": jsonReady(vs),
			"alerts": as,
			"store":  counts,
			"db":     a.cfg.DBPath,
		}
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(out))
		return health.Aggregate(vs, false)
	}
	if err := report.Status(a.stdout, vs, now, false); err != nil {
		return a.fail(err)
	}
	if len(as) > 0 {
		fmt.Fprintf(a.stdout, "\nrecent state changes\n")
		if err := report.Alerts(a.stdout, as, false); err != nil {
			return a.fail(err)
		}
	}
	fmt.Fprintf(a.stdout, "\nstate: %s\n", a.cfg.DBPath)
	return health.Aggregate(vs, false)
}

func jsonReady(vs []health.Verdict) []map[string]any {
	out := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, report.VerdictJSON(v))
	}
	return out
}

func (a *app) cmdHistory(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("history")
	limit := fs.Int("limit", 20, "how many beacons to show")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell history [--limit N] <slug>\n\nThe beacons recorded for one check, newest first, and whether each was signed.\n")
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
		fmt.Fprintln(a.stderr, "knell history: exactly one slug is required")
		return exitError
	}
	if err := a.local(); err != nil {
		return a.fail(err)
	}
	if _, err := a.st.GetCheck(context.Background(), slug); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return a.fail(fmt.Errorf("no check %q", slug))
		}
		return a.fail(err)
	}
	bs, err := a.st.RecentBeacons(context.Background(), slug, *limit)
	if err != nil {
		return a.fail(err)
	}
	if err := report.Beacons(a.stdout, bs, *jsonOut); err != nil {
		return a.fail(err)
	}
	return exitOK
}

func (a *app) cmdAlerts(args []string) int {
	fs, jsonOut, _ := a.newFlagSet("alerts")
	limit := fs.Int("limit", 20, "how many events to show")
	only := fs.String("slug", "", "restrict to one check")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, "usage: knell alerts [--limit N] [--slug S]\n\nWhen things went quiet and when they came back. This is the record that answers\n'was it down last Tuesday', not only 'is it down now'.\n")
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
	as, err := a.st.RecentAlerts(context.Background(), *limit)
	if err != nil {
		return a.fail(err)
	}
	if *only != "" {
		filtered := as[:0]
		for _, x := range as {
			if x.Slug == *only {
				filtered = append(filtered, x)
			}
		}
		as = filtered
	}
	if err := report.Alerts(a.stdout, as, *jsonOut); err != nil {
		return a.fail(err)
	}
	return exitOK
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"could not encode output"}`
	}
	return string(b)
}
