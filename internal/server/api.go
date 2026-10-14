package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/report"
	"github.com/0xCyrildev/knell/internal/sanitize"
	"github.com/0xCyrildev/knell/internal/sign"
	"github.com/0xCyrildev/knell/internal/store"
)

// handleStatus is the read side of the API: verdicts, computed the same way the
// CLI computes them.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	vs, err := s.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, body{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, report.VerdictJSON(v))
	}
	counts, _ := s.st.Counts(r.Context())
	writeJSON(w, http.StatusOK, body{
		"time":   s.now().UTC().Format(time.RFC3339),
		"checks": out,
		"store":  counts,
	})
}

func (s *Server) handleListChecks(w http.ResponseWriter, r *http.Request) {
	cs, err := s.st.ListChecks(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, body{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(cs))
	fp := s.keys.Fingerprints()
	for _, c := range cs {
		j := report.VerdictJSON(health.Evaluate(c, s.now()))
		j["key_id"] = fp[c.Slug]
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

type createRequest struct {
	Slug   string          `json:"slug"`
	Period json.RawMessage `json:"period"`
	Grace  json.RawMessage `json:"grace"`
	Note   string          `json:"note"`
}

// handleCreateCheck mints a signing key together with the check, and returns it
// exactly once — the response body is the only place the secret ever appears.
func (s *Server) handleCreateCheck(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req createRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, body{"error": "invalid JSON body: " + err.Error()})
		return
	}
	if !sign.ValidSlug(req.Slug) {
		writeJSON(w, http.StatusBadRequest, body{"error": "slug must match ^[a-z0-9][a-z0-9._-]{0,63}$"})
		return
	}
	period, err := parseDurationField(req.Period, "period")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, body{"error": err.Error()})
		return
	}
	grace, err := parseDurationField(req.Grace, "grace")
	if errors.Is(err, errFieldMissing) {
		grace = 0
		err = nil
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, body{"error": err.Error()})
		return
	}
	if period < 10*time.Second {
		writeJSON(w, http.StatusBadRequest, body{"error": "period must be at least 10s"})
		return
	}
	if grace < 0 || grace > 7*24*time.Hour {
		writeJSON(w, http.StatusBadRequest, body{"error": "grace must be between 0 and 168h"})
		return
	}
	note := sanitize.Text(req.Note)
	if err := s.st.AddCheck(r.Context(), store.Spec{
		Slug: req.Slug, Period: period, Grace: grace, Note: note,
	}); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, store.ErrExists) {
			code = http.StatusConflict
		}
		writeJSON(w, code, body{"error": err.Error()})
		return
	}
	secret, err := s.keys.Put(req.Slug, "")
	if err != nil {
		// A check without a key would silently never be beatable, so the row is
		// removed rather than left to look healthy.
		_ = s.st.DeleteCheck(r.Context(), req.Slug)
		writeJSON(w, http.StatusInternalServerError, body{"error": "could not create signing key: " + err.Error()})
		return
	}
	kid := store.KeyID(secret)
	if err := s.st.UpdateCheck(r.Context(), req.Slug, store.Patch{KeyID: &kid}); err != nil {
		s.log.Warn("storing key fingerprint", "slug", req.Slug, "err", err)
	}
	writeJSON(w, http.StatusCreated, body{
		"slug":           req.Slug,
		"period_seconds": int64(period / time.Second),
		"grace_seconds":  int64(grace / time.Second),
		"secret":         secret,
		"beat_path":      "/api/v1/beat/" + req.Slug,
		"note":           "the secret is shown once; store it now",
	})
}

func (s *Server) handleDeleteCheck(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !sign.ValidSlug(slug) {
		writeJSON(w, http.StatusBadRequest, body{"error": "invalid slug"})
		return
	}
	if err := s.st.DeleteCheck(r.Context(), slug); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeJSON(w, code, body{"error": err.Error()})
		return
	}
	if err := s.keys.Delete(slug); err != nil {
		s.log.Warn("deleting signing key", "slug", slug, "err", err)
	}
	s.eval.Forget(slug)
	writeJSON(w, http.StatusOK, body{"deleted": slug})
}

var errFieldMissing = errors.New("missing")

// parseDurationField accepts either `300` (seconds) or `"5m"`, because cron
// people and Go people both write configs.
func parseDurationField(raw json.RawMessage, name string) (time.Duration, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("%w: %s is required", errFieldMissing, name)
	}
	var num float64
	if err := json.Unmarshal(raw, &num); err == nil {
		if num <= 0 {
			return 0, fmt.Errorf("%s must be positive", name)
		}
		return time.Duration(num * float64(time.Second)), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf("%s must be a number of seconds or a duration string like %q", name, "1h30m")
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return parseDurationField(json.RawMessage(s), name)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return d, nil
}
