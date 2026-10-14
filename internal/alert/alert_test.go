package alert

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/store"
)

// safeBuf is a bytes.Buffer with a lock. A notify hook logs from its own
// goroutine, and a plain buffer is not a legal io.Writer for two threads — the
// race detector is right to complain about the sink, not about knell.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEvaluator(t *testing.T, notify string) (*Evaluator, *store.Store, *safeBuf) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "knell.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	buf := &safeBuf{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	return New(st, log, notify), st, buf
}

func verdict(slug string, state health.State, last time.Time, count int64, deadline time.Time) health.Verdict {
	return health.Verdict{
		Check:    health.Check{Slug: slug, Period: time.Hour, Last: &health.Beacon{Slug: slug, TS: last.Unix()}, BeaconCount: count},
		State:    state,
		Deadline: deadline,
		Since:    2 * time.Hour,
		DueIn:    -time.Hour,
		Overdue:  time.Hour,
	}
}

func waitForAlert(t *testing.T, st *store.Store, kind string) store.Alert {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		as, err := st.RecentAlerts(context.Background(), 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range as {
			if a.Kind == kind {
				return a
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no alert of kind %q arrived", kind)
	return store.Alert{}
}

func TestTransitionsFireOnce(t *testing.T) {
	e, st, _ := newEvaluator(t, "")
	now := time.Unix(1700000000, 0)
	silent := verdict("nightly", health.StateSilent, now.Add(-2*time.Hour), 4, now.Add(-time.Hour))
	recovered := verdict("nightly", health.StateOK, now, 5, now.Add(time.Hour))

	if got := e.Eval(context.Background(), now, []health.Verdict{silent}); len(got) != 1 {
		t.Fatalf("first sighting of silence should alert, got %d", len(got))
	}
	if got := e.Eval(context.Background(), now.Add(time.Minute), []health.Verdict{silent}); len(got) != 0 {
		t.Errorf("ongoing silence should not re-alert every sweep, got %d", len(got))
	}
	if got := e.Eval(context.Background(), now.Add(2*time.Minute), []health.Verdict{recovered}); len(got) != 1 {
		t.Errorf("recovery should alert, got %d", len(got))
	}
	as, err := st.RecentAlerts(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 2 {
		t.Fatalf("alerts = %+v, want silent then recovered", as)
	}
	// Newest first: the trail reads backwards in time, like a log.
	if as[0].Kind != string(KindRecovered) || as[1].Kind != string(KindSilent) {
		t.Errorf("alert order = %s, %s", as[0].Kind, as[1].Kind)
	}
	if !strings.Contains(as[1].Detail, "2h") {
		t.Errorf("a silent alert should say how long it has been quiet, got %q", as[1].Detail)
	}
}

func TestFreshCheckDoesNotAlert(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fresh := health.Verdict{
		Check: health.Check{Slug: "new", Period: time.Hour, CreatedAt: now.Add(-time.Minute)},
		State: health.StateNever,
	}
	e, _, _ := newEvaluator(t, "")
	if got := e.Eval(context.Background(), now, []health.Verdict{fresh}); len(got) != 0 {
		t.Errorf("`knell add` should not page anyone, got %d alerts", len(got))
	}
	// Past period+grace with no beacon at all, however, is exactly what a dead
	// man's switch is for — and the first sighting must say it was never seen,
	// not "last one was 0s ago".
	late := health.Verdict{
		Check:    health.Check{Slug: "new", Period: time.Hour, CreatedAt: now.Add(-3 * time.Hour)},
		State:    health.StateSilent,
		Deadline: now.Add(-time.Hour),
	}
	e2, _, _ := newEvaluator(t, "")
	if got := e2.Eval(context.Background(), now, []health.Verdict{late}); len(got) != 1 {
		t.Fatalf("a check that never reported should alert, got %d", len(got))
	} else if !strings.Contains(got[0].Detail, "no beacon ever arrived") {
		t.Errorf("the detail should distinguish never-reported from gone-quiet: %q", got[0].Detail)
	}
}

func TestPausedIsQuiet(t *testing.T) {
	e, _, _ := newEvaluator(t, "")
	now := time.Unix(1700000000, 0)
	v := health.Verdict{Check: health.Check{Slug: "s", Paused: true, Period: time.Minute}, State: health.StatePaused}
	if got := e.Eval(context.Background(), now, []health.Verdict{v}); len(got) != 0 {
		t.Errorf("a paused check produced %d alerts", len(got))
	}
}

func TestLateIsNotSilent(t *testing.T) {
	e, _, _ := newEvaluator(t, "")
	now := time.Unix(1700000000, 0)
	v := verdict("s", health.StateLate, now.Add(-2*time.Hour), 4, now.Add(5*time.Minute))
	if got := e.Eval(context.Background(), now, []health.Verdict{v}); len(got) != 0 {
		t.Errorf("late is inside the grace window; it must not alert, got %d", len(got))
	}
}

// A restart must not hide an outage that is still happening. The remembered
// previous state is only a duplicate filter, so a fresh evaluator re-announces.
func TestRestartReannouncesOngoingOutage(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "knell.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Unix(1700000000, 0)
	v := verdict("nightly", health.StateSilent, now.Add(-2*time.Hour), 4, now.Add(-time.Hour))

	first := New(st, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")
	first.Eval(context.Background(), now, []health.Verdict{v})
	second := New(st, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")
	if got := second.Eval(context.Background(), now.Add(time.Hour), []health.Verdict{v}); len(got) != 1 {
		t.Errorf("after a restart the outage was reported %d times, want 1", len(got))
	}
}

// A process that forgot an outage already on record must not re-log it inside the
// check's own window — that is an echo, and it is what a per-minute `knell check`
// cron entry would otherwise produce. Outside the window it becomes a nag, which
// TestRestartReannouncesOngoingOutage covers.
func TestForgetDoesNotReLogARecentOutage(t *testing.T) {
	e, st, _ := newEvaluator(t, "")
	now := time.Unix(1700000000, 0)
	v := verdict("nightly", health.StateSilent, now.Add(-2*time.Hour), 4, now.Add(-time.Hour))
	if got := e.Eval(context.Background(), now, []health.Verdict{v}); len(got) != 1 {
		t.Fatal("setup: expected the first silent alert")
	}
	e.Forget("nightly")
	if got := e.Eval(context.Background(), now.Add(time.Minute), []health.Verdict{v}); len(got) != 0 {
		t.Errorf("a forgotten-but-recently-recorded outage should not be re-logged, got %d", len(got))
	}
	waitForAlert(t, st, string(KindSilent))
}

func TestNotifyHookReceivesDetailsInEnv(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "hook.txt")
	// The hook is the operator's shell command; knell's contribution is that the
	// alert's data arrives as environment variables only.
	e, st, _ := newEvaluator(t, "printf '%s|%s|%s\\n' \"$KNELL_ALERT\" \"$KNELL_SLUG\" \"$KNELL_DETAIL\" > "+out)
	now := time.Unix(1700000000, 0)
	e.Eval(context.Background(), now, []health.Verdict{
		verdict("nightly", health.StateSilent, now.Add(-2*time.Hour), 4, now.Add(-time.Hour)),
	})
	waitForAlert(t, st, string(KindSilent))

	deadline := time.Now().Add(5 * time.Second)
	var b []byte
	for time.Now().Before(deadline) {
		var err error
		if b, err = os.ReadFile(out); err == nil && len(b) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := string(b)
	if !strings.HasPrefix(got, "silent|nightly|") {
		t.Fatalf("hook output = %q, want the alert kind, slug and detail", got)
	}
	if !strings.Contains(got, "expected a beacon by") {
		t.Errorf("hook output lost the detail: %q", got)
	}
}

// The hook inherits a curated environment: the admin token that unlocks the API
// must not reach a shell command that a slug could indirectly name.
func TestNotifyHookDoesNotInheritSecrets(t *testing.T) {
	t.Setenv("KNELL_ADMIN_TOKEN", "hunter2-not-for-hooks")
	dir := t.TempDir()
	out := filepath.Join(dir, "env.txt")
	e, st, _ := newEvaluator(t, "env > "+out)
	now := time.Unix(1700000000, 0)
	e.Eval(context.Background(), now, []health.Verdict{
		verdict("nightly", health.StateSilent, now.Add(-2*time.Hour), 4, now.Add(-time.Hour)),
	})
	waitForAlert(t, st, string(KindSilent))

	deadline := time.Now().Add(5 * time.Second)
	var b []byte
	for time.Now().Before(deadline) {
		if x, err := os.ReadFile(out); err == nil && len(x) > 0 {
			b = x
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(string(b), "hunter2-not-for-hooks") {
		t.Errorf("the hook inherited the admin token:\n%s", b)
	}
	if !strings.Contains(string(b), "KNELL_SLUG=nightly") {
		t.Errorf("the hook did not receive its own variables:\n%s", b)
	}
}

func TestNotifyFailureIsLoggedNotFatal(t *testing.T) {
	e, st, buf := newEvaluator(t, "exit 3")
	now := time.Unix(1700000000, 0)
	got := e.Eval(context.Background(), now, []health.Verdict{
		verdict("nightly", health.StateSilent, now.Add(-2*time.Hour), 4, now.Add(-time.Hour)),
	})
	if len(got) != 1 {
		t.Fatal("the alert itself should still be recorded")
	}
	waitForAlert(t, st, string(KindSilent))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), "notify command failed") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "notify command failed") {
		t.Errorf("a failing hook should be reported: %s", buf.String())
	}
}
