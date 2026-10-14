// Package report renders knell's state for a terminal or for jq.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/store"
)

// VerdictJSON is the machine-readable form of one check, shared by the CLI and
// the HTTP API so a dashboard and a cron job cannot disagree about a field name.
func VerdictJSON(v health.Verdict) map[string]any {
	last := map[string]any{}
	if v.Last != nil {
		last = map[string]any{
			"ts":          v.Last.TS,
			"at":          v.Last.At().UTC().Format(time.RFC3339),
			"received_at": v.Last.ReceivedAt,
			"source":      v.Last.Source,
			"signed":      v.Last.Sig != "",
			"note":        v.Last.Note,
		}
	}
	return map[string]any{
		"slug":            v.Slug,
		"state":           string(v.State),
		"period_seconds":  int64(v.Period / time.Second),
		"grace_seconds":   int64(v.Grace / time.Second),
		"paused":          v.Paused,
		"note":            v.Note,
		"last_beacon":     last,
		"beacons":         v.BeaconCount,
		"deadline":        v.Deadline.UTC().Format(time.RFC3339),
		"due_in_seconds":  int64(v.DueIn / time.Second),
		"overdue_seconds": int64(v.Overdue / time.Second),
		"since_seconds":   int64(v.Since / time.Second),
		"missed_periods":  v.Missed,
	}
}

// Status prints one row per check, worst first, and a trailing summary line
// that carries the exit-code meaning in words.
func Status(w io.Writer, vs []health.Verdict, now time.Time, jsonOut bool) error {
	if jsonOut {
		out := make([]map[string]any, 0, len(vs))
		for _, v := range vs {
			out = append(out, VerdictJSON(v))
		}
		return emit(w, map[string]any{"time": now.UTC().Format(time.RFC3339), "checks": out})
	}
	if len(vs) == 0 {
		_, err := fmt.Fprintln(w, "no checks configured — add one with: knell add <slug> --period 1h")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATE\tSLUG\tPERIOD\tGRACE\tLAST BEACON\tNEXT DUE\tNOTE")
	silent := 0
	for _, v := range vs {
		if v.State == health.StateSilent {
			silent++
		}
		last := "never"
		if v.Last != nil {
			last = health.Human(v.Since) + " ago"
		}
		due := "-"
		switch v.State {
		case health.StateSilent:
			due = "overdue " + health.Human(v.Overdue)
		case health.StatePaused:
			due = "paused"
		default:
			if v.DueIn > 0 {
				due = "in " + health.Human(v.DueIn)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			v.State, v.Slug, health.Human(v.Period), health.Human(v.Grace), last, due, truncate(v.Note, 40))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if silent == 0 {
		_, err := fmt.Fprintf(w, "\nno silence: %d check(s) reported within their grace window\n", len(vs))
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d of %d check(s) silent — %s\n", silent, len(vs), oldestSilent(vs, now))
	return err
}

func oldestSilent(vs []health.Verdict, now time.Time) string {
	var worst time.Duration
	for _, v := range vs {
		if v.State == health.StateSilent && v.Overdue > worst {
			worst = v.Overdue
		}
	}
	if worst == 0 {
		return "their grace window"
	}
	return "up to " + health.Human(worst) + " past due"
}

// Checks lists configuration plus the fingerprint of each signing key, never the
// key itself.
func Checks(w io.Writer, cs []health.Check, fingerprints map[string]string, jsonOut bool) error {
	if jsonOut {
		out := make([]map[string]any, 0, len(cs))
		for _, c := range cs {
			out = append(out, map[string]any{
				"slug":           c.Slug,
				"period_seconds": int64(c.Period / time.Second),
				"grace_seconds":  int64(c.Grace / time.Second),
				"paused":         c.Paused,
				"note":           c.Note,
				"created_at":     c.CreatedAt.UTC().Format(time.RFC3339),
				"beacons":        c.BeaconCount,
				"key_id":         fingerprints[c.Slug],
			})
		}
		return emit(w, out)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SLUG\tPERIOD\tGRACE\tPAUSED\tBEACONS\tCREATED\tKEY ID")
	for _, c := range cs {
		id := fingerprints[c.Slug]
		if id == "" {
			id = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%d\t%s\t%s\n",
			c.Slug, health.Human(c.Period), health.Human(c.Grace), c.Paused,
			c.BeaconCount, c.CreatedAt.UTC().Format(time.RFC3339), id)
	}
	return tw.Flush()
}

func Beacons(w io.Writer, bs []health.Beacon, jsonOut bool) error {
	if jsonOut {
		out := make([]map[string]any, 0, len(bs))
		for _, b := range bs {
			out = append(out, map[string]any{
				"ts": b.TS, "at": b.At().UTC().Format(time.RFC3339),
				"received_at": b.ReceivedAt, "source": b.Source,
				"signed": b.Sig != "", "nonce": b.Nonce, "sig": b.Sig, "note": b.Note,
			})
		}
		return emit(w, out)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tSOURCE\tSIGNED\tNONCE\tNOTE")
	for _, b := range bs {
		signed := "no"
		if b.Sig != "" {
			signed = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", b.At().Local().Format(time.RFC3339),
			b.Source, signed, short(b.Nonce), truncate(b.Note, 40))
	}
	return tw.Flush()
}

func Alerts(w io.Writer, as []store.Alert, jsonOut bool) error {
	if jsonOut {
		out := make([]map[string]any, 0, len(as))
		for _, a := range as {
			out = append(out, map[string]any{
				"slug": a.Slug, "kind": a.Kind,
				"at": time.Unix(a.TS, 0).UTC().Format(time.RFC3339), "detail": a.Detail,
			})
		}
		return emit(w, out)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tSTATE\tSLUG\tDETAIL")
	for _, a := range as {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", time.Unix(a.TS, 0).Local().Format(time.RFC3339),
			a.Kind, a.Slug, truncate(a.Detail, 60))
	}
	return tw.Flush()
}

func emit(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
