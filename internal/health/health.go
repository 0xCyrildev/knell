// Package health turns a check's schedule and its last beacon into a state,
// and that state into the exit codes cron and CI need.
package health

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

type State string

const (
	StateOK     State = "ok"
	StateLate   State = "late"
	StateSilent State = "silent"
	StateNever  State = "never"
	StatePaused State = "paused"
)

// Check is a monitored schedule. Period is how often a beacon is expected,
// Grace is the slack allowed before a miss becomes an alert.
type Check struct {
	Slug        string
	Period      time.Duration
	Grace       time.Duration
	Paused      bool
	Note        string
	CreatedAt   time.Time
	Last        *Beacon
	BeaconCount int64
}

type Beacon struct {
	Slug       string
	TS         int64
	ReceivedAt int64
	Source     string
	Nonce      string
	Sig        string
	Note       string
}

// At returns the instant a beacon is effectively attributable to: the claimed
// timestamp, which signing bounds to the skew window, falling back to arrival.
func (b *Beacon) At() time.Time {
	if b == nil {
		return time.Time{}
	}
	if b.TS > 0 {
		return time.Unix(b.TS, 0)
	}
	return time.Unix(b.ReceivedAt, 0)
}

type Verdict struct {
	Check
	State    State
	Deadline time.Time
	DueIn    time.Duration
	Overdue  time.Duration
	Since    time.Duration
	Missed   int64
}

// Evaluate is pure: same inputs, same verdict, so the CLI, the server's alert
// loop and the tests all agree on what "gone quiet" means.
func Evaluate(c Check, now time.Time) Verdict {
	v := Verdict{Check: c, State: StateOK}
	if c.Period <= 0 {
		c.Period = time.Minute
		v.Check = c
	}
	switch {
	case c.Paused:
		v.State = StatePaused
		return v
	case c.Last == nil:
		v.Deadline = c.CreatedAt.Add(c.Period + c.Grace)
		if now.Before(v.Deadline) {
			v.State = StateNever
		} else {
			v.State = StateSilent
			v.Overdue = now.Sub(v.Deadline)
		}
		v.DueIn = v.Deadline.Sub(now)
		return v
	}
	last := c.Last.At()
	v.Deadline = last.Add(c.Period + c.Grace)
	v.Since = now.Sub(last)
	v.DueIn = v.Deadline.Sub(now)
	if v.Missed = int64(now.Sub(last) / c.Period); v.Missed < 0 {
		v.Missed = 0
	}
	switch {
	case now.After(v.Deadline):
		v.State = StateSilent
		v.Overdue = now.Sub(v.Deadline)
	case now.After(last.Add(c.Period)):
		v.State = StateLate
	default:
		v.State = StateOK
	}
	return v
}

// Exit codes are a contract, so they are documented once and enforced here.
//
//	0  everything is within its grace window (late counts, unless strict)
//	1  at least one check is silent, or never reported past its grace
//	2  knell could not decide (bad flags, unreadable state) — fail closed
func (v Verdict) ExitCode(strict bool) int {
	switch v.State {
	case StateSilent:
		return 1
	case StateLate:
		if strict {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// Aggregate returns the worst code across verdicts: 1 if any is failing.
func Aggregate(vs []Verdict, strict bool) int {
	rc := 0
	for _, v := range vs {
		if c := v.ExitCode(strict); c > rc {
			rc = c
		}
	}
	return rc
}

// Rank orders a report worst-first: silent, late, never, ok, paused. Within a
// state, the most overdue or the lexicographically smallest slug comes first,
// so repeated runs of the same report are byte-stable.
var severity = map[State]int{
	StateSilent: 0,
	StateLate:   1,
	StateNever:  2,
	StateOK:     3,
	StatePaused: 4,
}

func Rank(vs []Verdict) {
	sort.SliceStable(vs, func(i, j int) bool { return less(vs[i], vs[j]) })
}

func less(a, b Verdict) bool {
	ra, rb := severity[a.State], severity[b.State]
	if ra != rb {
		return ra < rb
	}
	if a.State == StateSilent && a.Overdue != b.Overdue {
		return a.Overdue > b.Overdue
	}
	return a.Slug < b.Slug
}

// Human renders a duration the way a terminal reader expects: "30m", not
// "30m0s", and "26m13s" not "1573s". Components are assembled explicitly because
// Go's own String() pads every unit, which turns a schedule table into noise.
func Human(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d >= 24*time.Hour {
		days := int64(d / (24 * time.Hour))
		hours := int64((d - time.Duration(days)*24*time.Hour) / time.Hour)
		if hours == 0 {
			return strconv.FormatInt(days, 10) + "d"
		}
		return strconv.FormatInt(days, 10) + "d" + strconv.FormatInt(hours, 10) + "h"
	}
	d = d.Truncate(time.Second)
	h := int64(d / time.Hour)
	m := int64(d%time.Hour) / int64(time.Minute)
	s := int64(d%time.Minute) / int64(time.Second)
	switch {
	case h > 0 && m > 0 && s > 0:
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case h > 0 && s > 0:
		return fmt.Sprintf("%dh%ds", h, s)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
