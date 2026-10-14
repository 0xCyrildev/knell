// Package alert decides when a change of liveness state is worth recording or
// acting on, and runs the operator's notify command.
package alert

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/store"
)

type Kind string

const (
	KindSilent    Kind = "silent"
	KindRecovered Kind = "recovered"
	KindFirst     Kind = "first_beacon"
)

// Evaluator is stateful by design: "it went quiet" is a transition, not a
// property of one sample. The remembered previous state only suppresses
// duplicate alerts — it never decides the current state — and a process with no
// remembered state (a restart, or a single `knell check`) consults the alert
// table instead of assuming the outage was already announced.
type Evaluator struct {
	st     *store.Store
	log    *slog.Logger
	notify string

	// hooks are on when a command is configured; a read-only command such as
	// `knell check` turns them off so that looking cannot page anyone.
	hooks bool
	base  context.Context

	mu   sync.Mutex
	prev map[string]health.State
	wg   sync.WaitGroup
}

func New(st *store.Store, log *slog.Logger, notifyCmd string) *Evaluator {
	cmd := strings.TrimSpace(notifyCmd)
	return &Evaluator{
		st:     st,
		log:    log,
		notify: cmd,
		hooks:  cmd != "",
		base:   context.Background(),
		prev:   map[string]health.State{},
	}
}

// WithoutHooks records transitions but never runs the notify command.
func (e *Evaluator) WithoutHooks() *Evaluator {
	e.hooks = false
	return e
}

// Bind ties hook lifetime to a context, so an in-flight hook is cancelled on
// shutdown instead of outliving the process that started it.
func (e *Evaluator) Bind(ctx context.Context) { e.base = ctx }

// Wait drains in-flight hooks, bounded by ctx.
func (e *Evaluator) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Eval records an alert for every check that moved into or out of silent and
// returns the transitions it acted on, so callers and tests can see what fired.
func (e *Evaluator) Eval(ctx context.Context, now time.Time, vs []health.Verdict) []store.Alert {
	out := e.transitions(ctx, now, vs)
	for _, a := range out {
		if err := e.st.RecordAlert(ctx, a); err != nil {
			e.log.Error("recording alert", "slug", a.Slug, "kind", a.Kind, "err", err)
			continue
		}
		e.log.Info("state transition", "slug", a.Slug, "kind", a.Kind, "detail", a.Detail)
		if e.hooks {
			e.fire(a)
		}
	}
	return out
}

func (e *Evaluator) transitions(ctx context.Context, now time.Time, vs []health.Verdict) []store.Alert {
	out := []store.Alert{}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, v := range vs {
		before, seen := e.prev[v.Slug]
		e.prev[v.Slug] = v.State
		var a *store.Alert
		switch {
		case v.State == health.StateSilent && before != health.StateSilent:
			x := store.Alert{Slug: v.Slug, Kind: string(KindSilent), TS: now.Unix(),
				Detail: fmt.Sprintf("expected a beacon by %s, last one was %s ago",
					v.Deadline.UTC().Format(time.RFC3339), health.Human(v.Since))}
			if v.BeaconCount == 0 {
				x.Detail = fmt.Sprintf("no beacon ever arrived, and %s has passed since it was configured",
					health.Human(now.Sub(v.CreatedAt)))
			}
			a = &x
		case before == health.StateSilent && (v.State == health.StateOK || v.State == health.StateLate):
			a = &store.Alert{Slug: v.Slug, Kind: string(KindRecovered), TS: now.Unix(),
				Detail: fmt.Sprintf("beacon received %s ago", health.Human(v.Since))}
		case v.State == health.StateOK && before == health.StateNever && v.BeaconCount == 1:
			a = &store.Alert{Slug: v.Slug, Kind: string(KindFirst), TS: now.Unix(),
				Detail: "first beacon received"}
		}
		if a == nil {
			continue
		}
		// A process with no memory of the previous state — every `knell check`, and
		// every collector restart — must not re-log an outage that is already the
		// last thing on record. It re-announces only once the silence has outlasted
		// the check's own window: a nag, not an echo.
		if !seen && e.recentlyRecorded(ctx, a.Slug, a.Kind, now, v.Period+v.Grace) {
			continue
		}
		out = append(out, *a)
	}
	return out
}

func (e *Evaluator) recentlyRecorded(ctx context.Context, slug, kind string, now time.Time, within time.Duration) bool {
	if within <= 0 {
		return false
	}
	last, err := e.st.LastAlert(ctx, slug, kind)
	if err != nil {
		return false
	}
	return now.Sub(time.Unix(last.TS, 0)) < within
}

// fire runs the operator's notify command. Details are passed as environment
// variables instead of being interpolated into the shell string, so a slug or
// note written by someone else can never become shell syntax. Hooks run off the
// evaluation loop: a slow notification must not delay the next sweep.
func (e *Evaluator) fire(a store.Alert) {
	if e.notify == "" {
		return
	}
	cctx, cancel := context.WithTimeout(e.base, 30*time.Second)
	e.wg.Add(1)
	go func() {
		defer cancel()
		defer e.wg.Done()
		cmd := exec.CommandContext(cctx, "/bin/sh", "-c", e.notify)
		cmd.Env = append(passEnv(),
			"KNELL_ALERT="+a.Kind,
			"KNELL_SLUG="+a.Slug,
			"KNELL_DETAIL="+a.Detail,
			"KNELL_ALERT_AT="+time.Unix(a.TS, 0).UTC().Format(time.RFC3339),
		)
		if b, err := cmd.CombinedOutput(); err != nil {
			e.log.Error("notify command failed", "slug", a.Slug, "err", err,
				"output", strings.TrimSpace(string(b)))
		} else if s := strings.TrimSpace(string(b)); s != "" {
			e.log.Debug("notify command output", "slug", a.Slug, "output", s)
		}
	}()
}

// passEnv forwards only what a hook plausibly needs, so the server's own
// credentials (KNELL_ADMIN_TOKEN) cannot reach a child process.
func passEnv() []string {
	var out []string
	for _, k := range []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	if len(out) == 0 {
		out = append(out, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	return out
}

// Forget drops remembered state for a check that no longer exists.
func (e *Evaluator) Forget(slug string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.prev, slug)
}
