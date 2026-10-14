package health

import (
	"strings"
	"testing"
	"time"
)

func beaconAt(ts time.Time) *Beacon {
	return &Beacon{Slug: "x", TS: ts.Unix(), ReceivedAt: ts.Unix()}
}

func TestEvaluateStates(t *testing.T) {
	now := time.Unix(1700000000, 0)
	last := now.Add(-5 * time.Minute)
	cases := []struct {
		name string
		c    Check
		want State
	}{
		{"inside the period", Check{Slug: "a", Period: 10 * time.Minute, Grace: time.Minute, Last: beaconAt(last)}, StateOK},
		{"past the period, inside grace", Check{Slug: "b", Period: 4 * time.Minute, Grace: 2 * time.Minute, Last: beaconAt(last)}, StateLate},
		{"past the grace window", Check{Slug: "c", Period: time.Minute, Grace: time.Minute, Last: beaconAt(last)}, StateSilent},
		{"exactly on the deadline is late, not silent", Check{Slug: "d", Period: 4 * time.Minute, Grace: time.Minute, Last: beaconAt(last)}, StateLate},
		{"one second past the deadline is silent", Check{Slug: "e", Period: 4*time.Minute - time.Second, Grace: time.Minute, Last: beaconAt(last)}, StateSilent},
		{"never reported, still inside its first window", Check{Slug: "f", Period: time.Hour, Grace: time.Minute, CreatedAt: now.Add(-10 * time.Minute)}, StateNever},
		{"never reported, past its first window", Check{Slug: "g", Period: time.Hour, Grace: time.Minute, CreatedAt: now.Add(-2 * time.Hour)}, StateSilent},
		{"paused never alerts", Check{Slug: "h", Period: time.Minute, Paused: true, Last: beaconAt(now.Add(-30 * time.Hour))}, StatePaused},
		{"a beacon dated in the future is ok", Check{Slug: "i", Period: time.Minute, Grace: time.Minute, Last: beaconAt(now.Add(10 * time.Minute))}, StateOK},
	}
	for _, c := range cases {
		v := Evaluate(c.c, now)
		if v.State != c.want {
			t.Errorf("%s: state = %s, want %s (due=%s overdue=%s since=%s missed=%d)",
				c.name, v.State, c.want, v.DueIn, v.Overdue, v.Since, v.Missed)
		}
	}
}

func TestDeadlineMath(t *testing.T) {
	now := time.Unix(1700000000, 0)
	last := now.Add(-7 * time.Minute)
	v := Evaluate(Check{Slug: "a", Period: 10 * time.Minute, Grace: 3 * time.Minute, Last: beaconAt(last)}, now)
	if want := last.Add(13 * time.Minute); !v.Deadline.Equal(want) {
		t.Errorf("deadline = %s, want %s", v.Deadline, want)
	}
	if v.DueIn != 6*time.Minute {
		t.Errorf("DueIn = %s, want 6m", v.DueIn)
	}
	if v.Since != 7*time.Minute {
		t.Errorf("Since = %s, want 7m", v.Since)
	}
	if v.Missed != 0 {
		t.Errorf("Missed = %d, want 0 inside the period", v.Missed)
	}

	silent := Evaluate(Check{Slug: "b", Period: time.Minute, Grace: time.Minute, Last: beaconAt(last)}, now)
	// last is 7m ago, so the deadline was 5m ago.
	if silent.State != StateSilent || silent.Overdue != 5*time.Minute {
		t.Errorf("expected 5m overdue, got state=%s overdue=%s", silent.State, silent.Overdue)
	}
	if silent.Missed != 7 {
		t.Errorf("Missed = %d, want 7 periods elapsed", silent.Missed)
	}
}

func TestZeroPeriodIsClamped(t *testing.T) {
	// A check with no period would otherwise divide by zero in Missed and alert
	// instantly, so the model clamps it to a minute rather than mis-reporting.
	v := Evaluate(Check{Slug: "a", Period: 0, Last: beaconAt(time.Unix(1700000000, 0))}, time.Unix(1700000000, 0))
	if v.State != StateOK {
		t.Errorf("state = %s, want ok", v.State)
	}
}

func TestExitCodes(t *testing.T) {
	now := time.Unix(1700000000, 0)
	last := now.Add(-5 * time.Minute)
	late := Evaluate(Check{Slug: "l", Period: 4 * time.Minute, Grace: 2 * time.Minute, Last: beaconAt(last)}, now)
	ok := Evaluate(Check{Slug: "o", Period: 10 * time.Minute, Last: beaconAt(last)}, now)
	silent := Evaluate(Check{Slug: "s", Period: time.Minute, Last: beaconAt(last)}, now)
	paused := Evaluate(Check{Slug: "p", Paused: true, Period: time.Minute, Last: beaconAt(last)}, now)
	never := Evaluate(Check{Slug: "n", Period: time.Hour, CreatedAt: now}, now)

	if ok.ExitCode(false) != 0 || ok.ExitCode(true) != 0 {
		t.Error("an ok check must exit 0 in both modes")
	}
	if late.ExitCode(false) != 0 {
		t.Error("late must not fail by default; grace exists for a reason")
	}
	if late.ExitCode(true) != 1 {
		t.Error("--strict must promote late to a failure")
	}
	if silent.ExitCode(false) != 1 || silent.ExitCode(true) != 1 {
		t.Error("silent must exit 1")
	}
	if paused.ExitCode(true) != 0 {
		t.Error("a paused check is a deliberate silence, not a failure")
	}
	if never.ExitCode(true) != 0 {
		t.Error("a brand-new check that has not reported yet is not an outage")
	}

	if got := Aggregate([]Verdict{ok, silent, late}, false); got != 1 {
		t.Errorf("Aggregate = %d, want 1 (the worst child wins)", got)
	}
	if got := Aggregate([]Verdict{ok, late, paused}, false); got != 0 {
		t.Errorf("Aggregate = %d, want 0", got)
	}
	if got := Aggregate(nil, false); got != 0 {
		t.Errorf("Aggregate over no checks = %d, want 0: nothing is configured, nothing is broken", got)
	}
}

func TestRankOrdersWorstFirstAndIsStable(t *testing.T) {
	now := time.Unix(1700000000, 0)
	vs := []Verdict{
		Evaluate(Check{Slug: "zz-ok", Period: time.Hour, Last: beaconAt(now)}, now),
		Evaluate(Check{Slug: "mm-silent-old", Period: time.Minute, Last: beaconAt(now.Add(-time.Hour))}, now),
		Evaluate(Check{Slug: "aa-late", Period: 4 * time.Minute, Grace: 2 * time.Minute, Last: beaconAt(now.Add(-5 * time.Minute))}, now),
		Evaluate(Check{Slug: "bb-silent-new", Period: time.Minute, Last: beaconAt(now.Add(-10 * time.Minute))}, now),
		Evaluate(Check{Slug: "cc-paused", Paused: true, Period: time.Minute}, now),
	}
	Rank(vs)
	want := []string{"mm-silent-old", "bb-silent-new", "aa-late", "zz-ok", "cc-paused"}
	for i, w := range want {
		if vs[i].Slug != w {
			t.Errorf("position %d = %s, want %s (order: %v)", i, vs[i].Slug, w, slugs(vs))
		}
	}
	Rank(vs)
	for i, w := range want {
		if vs[i].Slug != w {
			t.Errorf("re-ranking changed the order at %d: %v", i, slugs(vs))
		}
	}
}

func slugs(vs []Verdict) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, string(v.State)+":"+v.Slug)
	}
	return out
}

func TestHuman(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{-5 * time.Second, "0s"},
		{0, "0s"},
		{46 * time.Second, "46s"},
		{90 * time.Second, "1m30s"},
		{30 * time.Minute, "30m"},
		{12*time.Minute + 46*time.Second, "12m46s"},
		{time.Hour, "1h"},
		{time.Hour + 30*time.Minute, "1h30m"},
		{time.Hour + 5*time.Second, "1h5s"},
		{25 * time.Hour, "1d1h"},
		{48 * time.Hour, "2d"},
		{73 * time.Hour, "3d1h"},
	}
	for _, c := range cases {
		if got := Human(c.in); got != c.want {
			t.Errorf("Human(%s) = %q, want %q", c.in, got, c.want)
		}
	}
	// A schedule table would be unreadable if a whole unit still printed its
	// zeroed children: "30m0s" is not information, it is padding.
	for _, d := range []time.Duration{time.Minute, time.Hour, 90 * time.Minute} {
		if got := Human(d); strings.HasSuffix(got, "0s") {
			t.Errorf("Human(%s) = %q, still carrying a trailing zero", d, got)
		}
	}
}

func TestBeaconAtPrefersClaimedTime(t *testing.T) {
	b := &Beacon{TS: 1700000000, ReceivedAt: 1700000100}
	if !b.At().Equal(time.Unix(1700000000, 0)) {
		t.Error("At should use the signed timestamp")
	}
	b2 := &Beacon{TS: 0, ReceivedAt: 1700000100}
	if !b2.At().Equal(time.Unix(1700000100, 0)) {
		t.Error("At should fall back to arrival when no timestamp is claimed")
	}
	var nilb *Beacon
	if !nilb.At().IsZero() {
		t.Error("a nil beacon should have no instant")
	}
}
