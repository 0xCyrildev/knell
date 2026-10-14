package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/sanitize"
	"github.com/0xCyrildev/knell/internal/sign"
	"github.com/0xCyrildev/knell/internal/store"
)

// Beacon header names. They are headers, not query parameters, because URLs
// end up in proxies, load balancers and browser history while headers usually
// do not — and knell's own access log never prints them.
const (
	HeaderTimestamp = "Knell-Timestamp"
	HeaderNonce     = "Knell-Nonce"
	HeaderSignature = "Knell-Signature"
)

// handleBeat is the unauthenticated entry point, so it is the path that carries
// the security guarantees: a beacon is admitted only if it is signed with the
// check's secret, its timestamp is inside the skew window, and its nonce has
// not been seen before — in memory now, and in the database across restarts.
func (s *Server) handleBeat(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !sign.ValidSlug(slug) {
		s.reject(w, r, slug, "bad_slug", http.StatusBadRequest, "invalid slug")
		return
	}
	ip := clientIP(r)
	if !s.limit.allow(ip, s.now()) {
		s.reject(w, r, slug, "rate_limited", http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	note, err := readNote(r, s.cfg.MaxBodyBytes)
	if err != nil {
		code, reason := http.StatusUnsupportedMediaType, "bad_body"
		if errors.Is(err, errTooLarge) {
			code, reason = http.StatusRequestEntityTooLarge, "body_too_large"
		}
		s.reject(w, r, slug, reason, code, err.Error())
		return
	}
	secret, err := s.keys.Get(slug)
	if err != nil {
		// A configured check with no key is an operator error, not an unknown
		// job: saying "no such check" would send someone looking for a typo in a
		// crontab line that is perfectly correct.
		if _, cerr := s.st.GetCheck(r.Context(), slug); cerr == nil {
			s.reject(w, r, slug, "no_key", http.StatusConflict,
				"check exists but has no signing key (knell rotate "+slug+")")
			return
		}
		s.reject(w, r, slug, "unknown_check", http.StatusNotFound, "no such check")
		return
	}

	tsRaw, nonce, sig := r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderNonce), r.Header.Get(HeaderSignature)
	if tsRaw == "" || nonce == "" || sig == "" {
		// No unsigned mode exists on purpose. Trusting "this came from loopback"
		// is not a capability check: one same-host TLS sidecar makes every
		// internet client a loopback peer. A check-in that cannot be signed should
		// be written by `knell beat` into the local database instead.
		s.reject(w, r, slug, "unsigned", http.StatusUnauthorized,
			"beacons must be signed (see: knell token "+slug+", or run knell beat on the collector host)")
		return
	}
	now := s.now()
	b := health.Beacon{Slug: slug, Note: note, Source: "http", ReceivedAt: now.Unix()}

	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		s.reject(w, r, slug, "bad_timestamp", http.StatusBadRequest, "Knell-Timestamp must be a unix second")
		return
	}
	if err := sign.Verify(secret, slug, nonce, sig, ts, now, s.cfg.Skew.Duration); err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, sign.ErrStale) || errors.Is(err, sign.ErrTimestamp) {
			code = http.StatusRequestTimeout
		}
		s.reject(w, r, slug, "signature:"+err.Error(), code, err.Error())
		return
	}
	if err := s.cache.Accept(slug+"|"+nonce, now); err != nil {
		switch {
		case errors.Is(err, sign.ErrReplay):
			s.reject(w, r, slug, "replay", http.StatusConflict, "nonce already accepted")
		default:
			// A full cache refuses rather than forgetting: forgetting would admit
			// a replay. The operator sees the pressure in /metrics.
			s.reject(w, r, slug, "replay_cache_full", http.StatusServiceUnavailable,
				"replay cache at capacity")
		}
		return
	}
	b.TS, b.Nonce, b.Sig = ts, nonce, sig

	if err := s.st.RecordBeacon(r.Context(), b); err != nil {
		switch {
		case errors.Is(err, store.ErrNonceUsed):
			s.reject(w, r, slug, "replay_durable", http.StatusConflict, "nonce already recorded")
		case errors.Is(err, store.ErrNotFound):
			s.reject(w, r, slug, "unknown_check", http.StatusNotFound, "no such check")
		default:
			s.log.Error("recording beacon", "slug", slug, "err", err)
			s.reject(w, r, slug, "store", http.StatusInternalServerError, "could not record beacon")
		}
		return
	}
	s.m.beaconsOK.Add(1)
	annotate(r, slug, "")
	// A beacon is an event, so the server sweeps that check immediately: an
	// outage is announced on its own timer, not on the next arbitrary tick.
	if c, err := s.st.GetCheck(r.Context(), slug); err == nil {
		v := health.Evaluate(c, s.now())
		s.eval.Eval(r.Context(), s.now(), []health.Verdict{v})
		writeJSON(w, http.StatusOK, body{
			"status": "accepted", "slug": slug, "state": string(v.State),
			"received_at": b.ReceivedAt, "due_in_seconds": int64(v.DueIn / time.Second),
		})
		return
	}
	writeJSON(w, http.StatusOK, body{"status": "accepted", "slug": slug, "received_at": b.ReceivedAt})
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request, slug, reason string, code int, msg string) {
	s.m.reject(reason)
	annotate(r, slug, reason)
	writeJSON(w, code, body{"error": msg, "reason": reason})
}

// errTooLarge separates "you sent too much" (413) from "you sent the wrong shape"
// (415), because a job retrying the wrong one wastes its budget.
var errTooLarge = errors.New("body too large")

// readNote accepts an optional JSON body carrying a short free-text note. The
// note is stored and printed, so it is length-capped and stripped of control
// characters before either happens: a terminal escape sequence in a note is an
// injection into whoever runs `knell status`.
func readNote(r *http.Request, max int64) (string, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return "", nil
	}
	if max <= 0 {
		max = 4096
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return "", fmt.Errorf("reading body")
	}
	if int64(len(body)) > max {
		return "", fmt.Errorf("%w: %d bytes, the limit is %d", errTooLarge, len(body), max)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", nil
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return "", fmt.Errorf("body must be application/json")
	}
	var doc struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("body must be a JSON object with an optional \"note\"")
	}
	return sanitize.Text(doc.Note), nil
}
