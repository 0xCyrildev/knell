// Package server is knell's HTTP collector: signed beacons in, status out.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xCyrildev/knell/internal/alert"
	"github.com/0xCyrildev/knell/internal/build"
	"github.com/0xCyrildev/knell/internal/config"
	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/sign"
	"github.com/0xCyrildev/knell/internal/store"
)

type Server struct {
	cfg   config.Config
	st    *store.Store
	keys  *store.Keys
	log   *slog.Logger
	cache *sign.ReplayCache
	limit *limiter
	eval  *alert.Evaluator
	m     *metrics
	srv   *http.Server

	// sweepMu guards the verdicts from the last sweep, which /metrics reports
	// instead of re-evaluating every check on every scrape: a dashboard polling
	// once a second should not serialise thousands of rows through one SQLite
	// connection and push beacon latency behind it.
	sweepMu sync.Mutex
	swept   []health.Verdict
	sweptAt time.Time

	// now is injectable so the skew window is testable without sleeping.
	now func() time.Time
}

func New(cfg config.Config, st *store.Store, keys *store.Keys, log *slog.Logger) *Server {
	return &Server{
		cfg:   cfg,
		st:    st,
		keys:  keys,
		log:   log,
		cache: sign.NewReplayCache(cfg.Skew.Duration, 100_000),
		limit: newLimiter(cfg.RatePerSec, cfg.RateBurst),
		eval:  alert.New(st, log, cfg.NotifyCmd),
		m:     &metrics{started: time.Now()},
		now:   time.Now,
	}
}

// SetClock replaces the server's reading of now. Tests use it to move a check
// across its deadline without sleeping; the CLI uses it so a report and the
// alerts it triggers are computed at one instant.
func (s *Server) SetClock(f func() time.Time) {
	if f != nil {
		s.now = f
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("POST /api/v1/beat/{slug}", s.handleBeat)
	mux.HandleFunc("GET /api/v1/status", s.requireAdmin(s.handleStatus))
	mux.HandleFunc("GET /api/v1/checks", s.requireAdmin(s.handleListChecks))
	mux.HandleFunc("POST /api/v1/checks", s.requireAdmin(s.handleCreateCheck))
	mux.HandleFunc("DELETE /api/v1/checks/{slug}", s.requireAdmin(s.handleDeleteCheck))
	mux.HandleFunc("/", s.handleNotFound)
	return s.recover(s.logRequests(mux))
}

// Run serves until ctx is cancelled, then drains in-flight requests.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("knell: listening on %s: %w", s.cfg.Listen, err)
	}
	s.srv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 14,
	}
	go s.loop(ctx)
	s.eval.Bind(ctx)
	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	s.log.Info("knell serving", "addr", s.cfg.Listen, "db", s.st.Path(), "eval", s.cfg.EvalEvery.String())
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("knell: shutting down: %w", err)
	}
	// Notify hooks were started on the serving context, which is now cancelled:
	// they are killed rather than abandoned, and we wait for them to return so a
	// stopped process has no child still writing to someone's inbox.
	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := s.eval.Wait(wctx); err != nil {
		s.log.Warn("notify hooks still running", "err", err)
	}
	wcancel()
	s.log.Info("knell stopped")
	return nil
}

// loop is the only thing that turns a database of beacons into an alert: it
// sweeps verdicts on a timer and prunes history.
func (s *Server) loop(ctx context.Context) {
	eval := time.NewTicker(s.cfg.EvalEvery.Duration)
	defer eval.Stop()
	// A nil channel never fires, which is how a disabled gc interval is
	// expressed without a second select statement.
	var gcC <-chan time.Time
	if s.cfg.GCEvery.Duration > 0 {
		gc := time.NewTicker(s.cfg.GCEvery.Duration)
		defer gc.Stop()
		gcC = gc.C
	}
	s.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-eval.C:
			s.sweep(ctx)
		case <-gcC:
			rep, err := s.st.GC(ctx, store.GCOptions{
				KeepPerCheck: s.cfg.KeepBeacons,
				MaxAge:       s.cfg.BeaconMaxAge.Duration,
				AlertMaxAge:  s.cfg.AlertMaxAge.Duration,
			})
			if err != nil {
				s.log.Error("gc failed", "err", err)
				continue
			}
			if rep.Warning != "" {
				s.log.Warn("gc", "warning", rep.Warning)
			}
			if rep.BeaconsDeleted+rep.AlertsDeleted > 0 {
				s.log.Info("gc", "beacons", rep.BeaconsDeleted, "alerts", rep.AlertsDeleted)
			}
		}
	}
}

func (s *Server) sweep(ctx context.Context) {
	vs, err := s.Status(ctx)
	if err != nil {
		s.log.Error("evaluating checks", "err", err)
		return
	}
	s.sweepMu.Lock()
	s.swept, s.sweptAt = vs, s.now()
	s.sweepMu.Unlock()
	s.eval.Eval(ctx, s.now(), vs)
	var silent []string
	for _, v := range vs {
		if v.State == health.StateSilent {
			silent = append(silent, v.Slug)
		}
	}
	if len(silent) > 0 {
		s.log.Warn("checks silent", "count", len(silent), "slugs", silent)
	}
}

// Status computes verdicts for every check. It is the same evaluation the CLI
// runs, so a report and the server can never disagree.
func (s *Server) Status(ctx context.Context) ([]health.Verdict, error) {
	cs, err := s.st.ListChecks(ctx)
	if err != nil {
		return nil, err
	}
	vs := make([]health.Verdict, 0, len(cs))
	for _, c := range cs {
		vs = append(vs, health.Evaluate(c, s.now()))
	}
	health.Rank(vs)
	return vs, nil
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.m.panics.Add(1)
				s.log.Error("panic recovered", "err", rec, "path", r.URL.Path,
					"stack", string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, body{"error": "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// logRequests deliberately records no header values: the signing material sits
// in a header and access logs are the least protected place in a deployment.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bi := &beatInfo{}
		start := time.Now()
		lw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lw, r.WithContext(context.WithValue(r.Context(), beatInfoKey, bi)))
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", lw.status,
			"ms", time.Since(start).Milliseconds(),
			"remote", clientIP(r),
		}
		if bi.slug != "" {
			attrs = append(attrs, "slug", bi.slug)
		}
		if bi.reason != "" {
			attrs = append(attrs, "reason", bi.reason)
		}
		s.log.Info("request", attrs...)
	})
}

type ctxKey int

const beatInfoKey ctxKey = 1

// beatInfo lets a handler annotate its own access-log line without the logging
// middleware having to know anything about the endpoint.
type beatInfo struct {
	slug   string
	reason string
}

func annotate(r *http.Request, slug, reason string) {
	if v := r.Context().Value(beatInfoKey); v != nil {
		bi := v.(*beatInfo)
		bi.slug, bi.reason = slug, reason
	}
}

// statusWriter records the response code for the access log. Forwarding
// WriteHeader is the whole point: a wrapper that only *stored* the code would
// log a 401 and send a 200, and a cron job reading the exit status of curl
// would believe a rejected beacon was accepted.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// requireAdmin guards mutation and read APIs. When no admin token is configured
// the routes refuse rather than running open: a forgotten env var should not be
// the difference between a monitored box and an unattended one.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Throttled like the beacon endpoint: an unthrottled bearer check is an
		// offline probe of the admin credential, and a wrong token should cost
		// the prober something.
		if !s.limit.allow("admin|"+clientIP(r), s.now()) {
			s.reject(w, r, "", "rate_limited", http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		tok := s.cfg.AdminToken
		if tok == "" {
			s.m.adminDeniedNoToken.Add(1)
			writeJSON(w, http.StatusServiceUnavailable, body{
				"error": "admin API disabled: start knell with KNELL_ADMIN_TOKEN set",
			})
			return
		}
		got := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(got) <= len(prefix) || got[:len(prefix)] != prefix {
			s.m.adminDeniedNoAuth.Add(1)
			writeJSON(w, http.StatusUnauthorized, body{"error": "missing bearer token"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(tok)) != 1 {
			s.m.adminDeniedBadAuth.Add(1)
			writeJSON(w, http.StatusForbidden, body{"error": "invalid token"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, body{
		"ok": true, "time": s.now().UTC().Format(time.RFC3339), "version": build.Short(),
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, body{"error": "not found"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encoding response", http.StatusInternalServerError)
	}
}

type body map[string]any

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter is a small per-key token bucket. Only the beacon endpoint needs it:
// everything else is either authenticated or trivially cheap.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	last    time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newLimiter(ratePerSec float64, burst int) *limiter {
	if ratePerSec <= 0 {
		ratePerSec = 5
	}
	if burst <= 0 {
		burst = 20
	}
	return &limiter{
		rate: ratePerSec, burst: float64(burst),
		buckets: map[string]*bucket{}, last: time.Now(),
	}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 10_000 {
			l.pruneLocked(now)
		}
		if len(l.buckets) > 10_000 {
			return false
		}
		b = &bucket{tokens: l.burst, seen: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.seen).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.seen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.seen) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

type metrics struct {
	beaconsOK          atomic.Int64
	rejected           sync.Map // reason -> *atomic.Int64
	adminDeniedNoToken atomic.Int64
	adminDeniedNoAuth  atomic.Int64
	adminDeniedBadAuth atomic.Int64
	panics             atomic.Int64
	started            time.Time
}

func (m *metrics) reject(reason string) {
	v, ok := m.rejected.Load(reason)
	if !ok {
		v, _ = m.rejected.LoadOrStore(reason, &atomic.Int64{})
	}
	v.(*atomic.Int64).Add(1)
}

// handleMetrics answers in Prometheus text format. The gauges are computed from
// live verdicts rather than remembered from the last sweep, so a server that has
// just started cannot report "0 checks" to a dashboard that is about to alert on
// exactly that.
// metricsVerdicts prefers the last sweep's result; before the first sweep (or if
// the sweep is disabled) it computes on demand so a freshly started server never
// reports a deployment with checks as "0 checks".
func (s *Server) metricsVerdicts(ctx context.Context) []health.Verdict {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	if s.swept != nil {
		return s.swept
	}
	vs, err := s.Status(ctx)
	if err != nil {
		s.log.Warn("metrics could not read checks", "err", err)
		return nil
	}
	return vs
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.limit.allow("admin|"+clientIP(r), s.now()) {
		s.reject(w, r, "", "rate_limited", http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	vs := s.metricsVerdicts(r.Context())
	byState := map[health.State]int64{}
	for _, v := range vs {
		byState[v.State]++
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# HELP knell_uptime_seconds Server uptime.\n# TYPE knell_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "knell_uptime_seconds %d\n", int64(time.Since(s.m.started).Seconds()))
	fmt.Fprintf(&b, "# HELP knell_beacons_accepted_total Signed beacons admitted.\n# TYPE knell_beacons_accepted_total counter\n")
	fmt.Fprintf(&b, "knell_beacons_accepted_total %d\n", s.m.beaconsOK.Load())
	fmt.Fprintf(&b, "# HELP knell_beacons_rejected_total Beacons refused, by reason.\n# TYPE knell_beacons_rejected_total counter\n")
	s.m.rejected.Range(func(k, v any) bool {
		fmt.Fprintf(&b, "knell_beacons_rejected_total{reason=%q} %d\n", k, v.(*atomic.Int64).Load())
		return true
	})
	fmt.Fprintf(&b, "# HELP knell_checks Configured checks.\n# TYPE knell_checks gauge\n")
	fmt.Fprintf(&b, "knell_checks %d\n", len(vs))
	fmt.Fprintf(&b, "# HELP knell_checks_by_state Checks in each liveness state.\n# TYPE knell_checks_by_state gauge\n")
	for _, state := range []health.State{
		health.StateOK, health.StateLate, health.StateSilent, health.StateNever, health.StatePaused,
	} {
		fmt.Fprintf(&b, "knell_checks_by_state{state=%q} %d\n", string(state), byState[state])
	}
	fmt.Fprintf(&b, "# HELP knell_admin_denied_total Admin API refusals, by cause.\n# TYPE knell_admin_denied_total counter\n")
	fmt.Fprintf(&b, "knell_admin_denied_total{cause=\"no_token_configured\"} %d\n", s.m.adminDeniedNoToken.Load())
	fmt.Fprintf(&b, "knell_admin_denied_total{cause=\"missing_bearer\"} %d\n", s.m.adminDeniedNoAuth.Load())
	fmt.Fprintf(&b, "knell_admin_denied_total{cause=\"bad_bearer\"} %d\n", s.m.adminDeniedBadAuth.Load())
	fmt.Fprintf(&b, "# HELP knell_panics_recovered_total Panics caught by the HTTP middleware.\n# TYPE knell_panics_recovered_total counter\n")
	fmt.Fprintf(&b, "knell_panics_recovered_total %d\n", s.m.panics.Load())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, b.String())
}
