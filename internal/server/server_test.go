package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xCyrildev/knell/internal/config"
	"github.com/0xCyrildev/knell/internal/health"
	"github.com/0xCyrildev/knell/internal/sign"
	"github.com/0xCyrildev/knell/internal/store"
)

var fixedNow = time.Unix(1700000000, 0).UTC()

type harness struct {
	t      *testing.T
	cfg    config.Config
	st     *store.Store
	keys   *store.Keys
	srv    *Server
	ts     *httptest.Server
	logs   *bytes.Buffer
	secret string
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DBPath = filepath.Join(dir, "knell.db")
	cfg.KeysPath = filepath.Join(dir, "keys.json")
	cfg.AdminToken = ""
	cfg.NotifyCmd = ""
	cfg.Skew = config.Dur{Duration: 15 * time.Minute}
	if mutate != nil {
		mutate(&cfg)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	keys, err := store.OpenKeys(cfg.KeysPath)
	if err != nil {
		t.Fatalf("opening keys: %v", err)
	}
	srv := New(cfg, st, keys, logger)
	srv.SetClock(func() time.Time { return fixedNow })
	ts := httptest.NewServer(srv.Handler())

	h := &harness{t: t, cfg: cfg, st: st, keys: keys, srv: srv, ts: ts, logs: logs}
	t.Cleanup(func() {
		ts.Close()
		st.Close()
	})
	return h
}

// addCheck creates a check and its key the way the CLI would.
func (h *harness) addCheck(slug string, period, grace time.Duration) string {
	h.t.Helper()
	ctx := context.Background()
	if err := h.st.AddCheck(ctx, store.Spec{Slug: slug, Period: period, Grace: grace}); err != nil {
		h.t.Fatalf("AddCheck(%s): %v", slug, err)
	}
	secret, err := h.keys.Put(slug, "")
	if err != nil {
		h.t.Fatalf("Put(%s): %v", slug, err)
	}
	h.secret = secret
	return secret
}

func (h *harness) signFor(slug, secret string, ts int64, nonce string) string {
	h.t.Helper()
	sig, err := sign.Signature(secret, slug, ts, nonce)
	if err != nil {
		h.t.Fatalf("signing: %v", err)
	}
	return sig
}

func (h *harness) url(p string) string { return h.ts.URL + p }

func (h *harness) post(path string, hdr map[string]string, body io.Reader) (*http.Response, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.url(path), body)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := h.ts.Client().Do(req)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func (h *harness) get(path string, token string) (*http.Response, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.url(path), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := h.ts.Client().Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func (h *harness) signedBeat(slug, secret, nonce string, ts int64) (*http.Response, []byte) {
	h.t.Helper()
	return h.post("/api/v1/beat/"+slug, map[string]string{
		HeaderTimestamp: fmt.Sprint(ts),
		HeaderNonce:     nonce,
		HeaderSignature: h.signFor(slug, secret, ts, nonce),
	}, nil)
}

func beacons(t *testing.T, st *store.Store, slug string) []health.Beacon {
	t.Helper()
	bs, err := st.RecentBeacons(context.Background(), slug, 100)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func TestBeatAcceptsAValidSignedBeacon(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	res, body := h.signedBeat("nightly", secret, strings.Repeat("a", 32), fixedNow.Unix())
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", res.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("body is not JSON: %s", body)
	}
	if out["status"] != "accepted" || out["state"] != string(health.StateOK) {
		t.Errorf("body = %v, want accepted/ok", out)
	}
	bs := beacons(t, h.st, "nightly")
	if len(bs) != 1 || bs[0].Sig == "" || bs[0].Source != "http" {
		t.Errorf("recorded beacon = %+v", bs)
	}
}

// TestRejectionsReachTheWire is a regression guard: a wrapper that records a
// status code without forwarding it makes every rejection look like an
// acceptance to curl, cron and CI.
func TestRejectionsReachTheWire(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	other := h.addCheck("sibling", time.Hour, time.Minute)

	cases := []struct {
		name   string
		hdr    map[string]string
		want   int
		reason string
	}{
		{"unsigned", map[string]string{}, http.StatusUnauthorized, "unsigned"},
		{
			" forged signature",
			map[string]string{
				HeaderTimestamp: fmt.Sprint(fixedNow.Unix()),
				HeaderNonce:     strings.Repeat("b", 32),
				HeaderSignature: strings.Repeat("c", 64),
			},
			http.StatusUnauthorized, "signature:invalid signature",
		},
		{
			"signature from a different check's key",
			map[string]string{
				HeaderTimestamp: fmt.Sprint(fixedNow.Unix()),
				HeaderNonce:     strings.Repeat("d", 32),
				HeaderSignature: h.signFor("nightly", other, fixedNow.Unix(), strings.Repeat("d", 32)),
			},
			http.StatusUnauthorized, "signature:invalid signature",
		},
		{
			"stale timestamp",
			map[string]string{
				HeaderTimestamp: fmt.Sprint(fixedNow.Add(-2 * time.Hour).Unix()),
				HeaderNonce:     strings.Repeat("e", 32),
				HeaderSignature: h.signFor("nightly", secret, fixedNow.Add(-2*time.Hour).Unix(), strings.Repeat("e", 32)),
			},
			http.StatusRequestTimeout, "signature:timestamp outside the accepted window",
		},
		{
			"nonce at the limit is accepted",
			map[string]string{
				HeaderTimestamp: fmt.Sprint(fixedNow.Add(-15 * time.Minute).Unix()),
				HeaderNonce:     strings.Repeat("f", 32),
				HeaderSignature: h.signFor("nightly", secret, fixedNow.Add(-15*time.Minute).Unix(), strings.Repeat("f", 32)),
			},
			http.StatusOK, "",
		},
		{
			"malformed nonce",
			map[string]string{
				HeaderTimestamp: fmt.Sprint(fixedNow.Unix()),
				HeaderNonce:     "not-hex",
				HeaderSignature: strings.Repeat("0", 64),
			},
			http.StatusUnauthorized, "signature:invalid nonce",
		},
		{
			"non-numeric timestamp",
			map[string]string{
				HeaderTimestamp: "soon",
				HeaderNonce:     strings.Repeat("1", 32),
				HeaderSignature: strings.Repeat("0", 64),
			},
			http.StatusBadRequest, "bad_timestamp",
		},
	}
	for _, c := range cases {
		res, body := h.post("/api/v1/beat/nightly", c.hdr, nil)
		if res.StatusCode != c.want {
			t.Errorf("%s: status = %d, want %d (%s)", c.name, res.StatusCode, c.want, body)
		}
		if c.reason != "" && !strings.Contains(string(body), c.reason) {
			t.Errorf("%s: body %q does not mention %q", c.name, body, c.reason)
		}
	}
	// Only the one legitimate acceptance was recorded.
	if got := len(beacons(t, h.st, "nightly")); got != 1 {
		t.Errorf("record %d beacons, want 1: a rejection must not leave a row", got)
	}
}

func TestBeatReplayIsRefusedTwiceOver(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	nonce := strings.Repeat("9", 32)

	res, _ := h.signedBeat("nightly", secret, nonce, fixedNow.Unix())
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first beacon = %d", res.StatusCode)
	}
	res, body := h.signedBeat("nightly", secret, nonce, fixedNow.Unix())
	if res.StatusCode != http.StatusConflict {
		t.Errorf("replay status = %d, want 409 (%s)", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "replay") {
		t.Errorf("body %q should name the reason", body)
	}

	// A restart empties the in-memory cache. The database's unique constraint is
	// what keeps a captured beacon from being re-admitted, so a second server
	// over the same files must still refuse.
	st2, err := store.Open(h.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	keys2, err := store.OpenKeys(h.cfg.KeysPath)
	if err != nil {
		t.Fatal(err)
	}
	srv2 := New(h.cfg, st2, keys2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv2.SetClock(func() time.Time { return fixedNow })
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	res2, err := ts2.Client().Post(ts2.URL+"/api/v1/beat/nightly", "", strings.NewReader(""))
	if err == nil {
		res2.Body.Close()
		if res2.StatusCode != http.StatusUnauthorized {
			t.Errorf("unsigned beacon after restart = %d, want 401", res2.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, ts2.URL+"/api/v1/beat/nightly", nil)
	req.Header.Set(HeaderTimestamp, fmt.Sprint(fixedNow.Unix()))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, h.signFor("nightly", secret, fixedNow.Unix(), nonce))
	r, err := ts2.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusConflict {
		t.Errorf("durable replay = %d, want 409 (%s)", r.StatusCode, b)
	}
	if len(beacons(t, st2, "nightly")) != 1 {
		t.Error("a replay added a row")
	}
}

func TestBeatUnknownAndInvalidSlugs(t *testing.T) {
	h := newHarness(t, nil)
	res, _ := h.post("/api/v1/beat/nope", nil, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("unknown check = %d, want 404", res.StatusCode)
	}
	for _, bad := range []string{"..", "A%2fB", "%2e%2e", "over" + strings.Repeat("x", 64)} {
		res, _ := h.post("/api/v1/beat/"+bad, nil, nil)
		if res.StatusCode == http.StatusOK {
			t.Errorf("slug %q was accepted", bad)
		}
	}
}

// There is no unsigned mode, from any address. Trusting "this came from loopback"
// is not a capability check: the documented deployment — a TLS sidecar on the same
// host — makes every remote client a loopback peer, so a mode that believed the
// peer would let anyone on the internet check in on your jobs.
func TestUnsignedBeaconsAreAlwaysRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.addCheck("nightly", time.Hour, time.Minute)

	res, body := h.post("/api/v1/beat/nightly", nil, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("loopback unsigned beacon = %d, want 401 (%s)", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "signed") {
		t.Errorf("the refusal should say what to do: %s", body)
	}

	req, _ := http.NewRequest(http.MethodPost, h.url("/api/v1/beat/nightly"), nil)
	req.RemoteAddr = "203.0.113.9:4444"
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("remote unsigned beacon = %d, want 401", rec.Code)
	}

	// Forwarded-for must not be able to claim locality either.
	req, _ = http.NewRequest(http.MethodPost, h.url("/api/v1/beat/nightly"), nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rec = httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a spoofed X-Forwarded-For = %d, want 401", rec.Code)
	}
	if len(beacons(t, h.st, "nightly")) != 0 {
		t.Error("a refused beacon left a row behind")
	}
}

func TestNoteIsSanitizedAndBounded(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	note := "backup done\x1b[31mRED\x1b[0m\nsecond line\x00null " + strings.Repeat("x", 400)
	body := `{"note":` + jsonQuote(note) + `}`

	nonce := strings.Repeat("7", 32)
	res, resp := h.post("/api/v1/beat/nightly", map[string]string{
		HeaderTimestamp: fmt.Sprint(fixedNow.Unix()),
		HeaderNonce:     nonce,
		HeaderSignature: h.signFor("nightly", secret, fixedNow.Unix(), nonce),
		"Content-Type":  "application/json",
	}, strings.NewReader(body))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", res.StatusCode, resp)
	}
	stored := beacons(t, h.st, "nightly")[0].Note
	if strings.ContainsAny(stored, "\x1b\x00\n") {
		t.Errorf("stored note kept control characters: %q", stored)
	}
	if len(stored) > 200 {
		t.Errorf("stored note is %d bytes, want a 200-rune cap", len(stored))
	}
	if !strings.Contains(stored, "backup done") {
		t.Errorf("note lost its content: %q", stored)
	}

	// An oversize body is refused rather than read into memory.
	huge := `{"note":"` + strings.Repeat("y", 8192) + `"}`
	res, _ = h.post("/api/v1/beat/nightly", map[string]string{
		"Content-Type": "application/json",
	}, strings.NewReader(huge))
	if res.StatusCode == http.StatusOK {
		t.Error("an oversized body was accepted")
	}
}

func TestWrongContentTypeIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	nonce := strings.Repeat("3", 32)
	res, _ := h.post("/api/v1/beat/nightly", map[string]string{
		HeaderTimestamp: fmt.Sprint(fixedNow.Unix()),
		HeaderNonce:     nonce,
		HeaderSignature: h.signFor("nightly", secret, fixedNow.Unix(), nonce),
		"Content-Type":  "application/x-www-form-urlencoded",
	}, strings.NewReader("note=hi"))
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", res.StatusCode)
	}
}

func TestRateLimitPerClient(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.RatePerSec = 1
		c.RateBurst = 2
	})
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	codes := []int{}
	for i := 0; i < 5; i++ {
		res, _ := h.signedBeat("nightly", secret, fmt.Sprintf("%032x", i), fixedNow.Unix())
		codes = append(codes, res.StatusCode)
	}
	saw429 := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			saw429 = true
		}
	}
	if !saw429 {
		t.Errorf("burst of 5 with rate 1/s and burst 2 should trip the limiter: %v", codes)
	}
	if codes[0] != http.StatusOK {
		t.Errorf("the first beacon should always pass: %v", codes)
	}
}

func TestAdminApiMatrix(t *testing.T) {
	h := newHarness(t, nil)
	res, body := h.get("/api/v1/status", "")
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("no token configured: status = %d, want 503 (%s)", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "KNELL_ADMIN_TOKEN") {
		t.Errorf("the refusal should say how to enable the API: %s", body)
	}

	// With a token configured, every failure mode is distinct and no route runs
	// open on a forgotten environment variable.
	h2 := newHarness(t, func(c *config.Config) { c.AdminToken = "s3cr3t" })
	h2.addCheck("nightly", time.Hour, time.Minute)
	if res, _ := h2.get("/api/v1/status", ""); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing bearer = %d, want 401", res.StatusCode)
	}
	if res, _ := h2.get("/api/v1/status", "wrong"); res.StatusCode != http.StatusForbidden {
		t.Errorf("wrong bearer = %d, want 403", res.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, h2.url("/api/v1/status"), nil)
	req.Header.Set("Authorization", "s3cr3t") // no scheme
	rec := httptest.NewRecorder()
	h2.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a token without the Bearer scheme = %d, want 401", rec.Code)
	}
	if res, _ := h2.get("/api/v1/status", "s3cr3t"); res.StatusCode != http.StatusOK {
		t.Errorf("valid bearer = %d, want 200", res.StatusCode)
	}
}

func TestAdminCreateAndDelete(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.AdminToken = "s3cr3t" })
	res, body := h.post("/api/v1/checks", map[string]string{
		"Authorization": "Bearer s3cr3t",
		"Content-Type":  "application/json",
	}, strings.NewReader(`{"slug":"from-api","period":"1h","grace":600,"note":"built by CI"}`))
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (%s)", res.StatusCode, body)
	}
	var created map[string]any
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	secret, _ := created["secret"].(string)
	if !sign.ValidSecret(secret) {
		t.Errorf("created check returned no usable secret: %v", created["secret"])
	}
	if created["beat_path"] != "/api/v1/beat/from-api" {
		t.Errorf("beat_path = %v", created["beat_path"])
	}
	if !h.keys.Has("from-api") {
		t.Error("the key was not stored")
	}

	// A beacon signed with the returned key must be accepted: the two halves of
	// the API have to agree on the key material.
	nonce := strings.Repeat("5", 32)
	res, body = h.signedBeat("from-api", secret, nonce, fixedNow.Unix())
	if res.StatusCode != http.StatusOK {
		t.Errorf("beacon with the created key = %d (%s)", res.StatusCode, body)
	}

	res, _ = h.post("/api/v1/checks", map[string]string{
		"Authorization": "Bearer s3cr3t",
		"Content-Type":  "application/json",
	}, strings.NewReader(`{"slug":"from-api","period":"1h"}`))
	if res.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create = %d, want 409", res.StatusCode)
	}

	for _, bad := range []string{
		`{"slug":"Bad Slug","period":"1h"}`,
		`{"slug":"ok-one"}`,
		`{"slug":"ok-two","period":"0"}`,
		`{"slug":"ok-three","period":"-5s"}`,
		`{"slug":"ok-four","period":"1h","grace":"9999h"}`,
		`{"slug":"ok-five","period":"1h","unexpected":1}`,
	} {
		res, _ := h.post("/api/v1/checks", map[string]string{
			"Authorization": "Bearer s3cr3t",
			"Content-Type":  "application/json",
		}, strings.NewReader(bad))
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", bad, res.StatusCode)
		}
	}

	res, _ = h.post("/api/v1/checks/from-api", map[string]string{"Authorization": "Bearer s3cr3t"}, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("POST is not a delete: %d", res.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodDelete, h.url("/api/v1/checks/from-api"), nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	r, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Errorf("delete = %d, want 200", r.StatusCode)
	}
	if h.keys.Has("from-api") {
		t.Error("deleting a check left its signing key behind")
	}
	req, _ = http.NewRequest(http.MethodDelete, h.url("/api/v1/checks/from-api"), nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	r2, _ := h.ts.Client().Do(req)
	r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Errorf("deleting twice = %d, want 404", r2.StatusCode)
	}
}

func TestStatusAndChecksJSON(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.AdminToken = "s3cr3t" })
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	h.addCheck("quiet", time.Hour, time.Minute)
	// One check reported, one never: the report must distinguish them.
	res, _ := h.signedBeat("nightly", secret, strings.Repeat("1", 32), fixedNow.Unix())
	if res.StatusCode != http.StatusOK {
		t.Fatal("beat failed")
	}

	res, body := h.get("/api/v1/status", "s3cr3t")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var doc struct {
		Time   string           `json:"time"`
		Checks []map[string]any `json:"checks"`
		Store  map[string]any   `json:"store"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("status body: %v\n%s", err, body)
	}
	if len(doc.Checks) != 2 {
		t.Fatalf("got %d checks, want 2: %s", len(doc.Checks), body)
	}
	states := map[string]string{}
	for _, c := range doc.Checks {
		states[c["slug"].(string)] = c["state"].(string)
	}
	if states["nightly"] != "ok" {
		t.Errorf("nightly = %q, want ok", states["nightly"])
	}
	if states["quiet"] != "never" {
		t.Errorf("quiet = %q, want never (a fresh check is not yet an outage)", states["quiet"])
	}
	// The wire must never carry key material, not even a fingerprint of a key
	// the caller is not entitled to.
	if strings.Contains(string(body), secret) {
		t.Error("the status response contained a signing secret")
	}

	res, body = h.get("/api/v1/checks", "s3cr3t")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("checks = %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "key_id") {
		t.Errorf("the checks listing should show key fingerprints: %s", body)
	}
}

func TestMetricsAndHealthz(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	h.signedBeat("nightly", secret, strings.Repeat("a", 32), fixedNow.Unix())
	h.signedBeat("nightly", secret, strings.Repeat("a", 32), fixedNow.Unix()) // replay
	h.post("/api/v1/beat/nightly", nil, nil)                                  // unsigned

	res, body := h.get("/metrics", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("metrics = %d", res.StatusCode)
	}
	text := string(body)
	for _, want := range []string{
		"knell_beacons_accepted_total 1",
		`knell_beacons_rejected_total{reason="replay"} 1`,
		`knell_beacons_rejected_total{reason="unsigned"} 1`,
		"knell_checks 1",
		`knell_checks_by_state{state="ok"} 1`,
		`knell_checks_by_state{state="silent"} 0`,
		"knell_uptime_seconds",
		`knell_admin_denied_total{cause="no_token_configured"}`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, secret) || strings.Contains(text, "aaaaaaaaaaaaaaaaaaaaaa") {
		t.Error("metrics leaked beacon signing material")
	}

	res, body = h.get("/healthz", "")
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":true`) {
		t.Errorf("healthz = %d %s", res.StatusCode, body)
	}
}

// TestAccessLogCarriesNoSecrets is the reason the header names are headers: the
// only unauthenticated endpoint has its signing material logged away from any
// log line knell itself writes.
func TestAccessLogCarriesNoSecrets(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Hour, time.Minute)
	nonce := strings.Repeat("4", 32)
	sig := h.signFor("nightly", secret, fixedNow.Unix(), nonce)
	res, _ := h.signedBeat("nightly", secret, nonce, fixedNow.Unix())
	if res.StatusCode != http.StatusOK {
		t.Fatal("beat should have been accepted")
	}
	logged := h.logs.String()
	for _, leak := range []string{secret, sig, nonce} {
		if strings.Contains(logged, leak) {
			t.Errorf("the access log contains %q\n%s", leak, logged)
		}
	}
	if !strings.Contains(logged, "slug=nightly") {
		t.Errorf("the access log should still be useful: %s", logged)
	}
}

func TestUnknownRoutesAndMethodNotMatches(t *testing.T) {
	h := newHarness(t, nil)
	res, _ := h.get("/nope", "")
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404", res.StatusCode)
	}
	res, _ = h.get("/api/v1/beat/nightly", "")
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("GET on the beat route = %d, want 404 from the method-aware mux", res.StatusCode)
	}
}

func TestSweepRecordsSilence(t *testing.T) {
	h := newHarness(t, nil)
	secret := h.addCheck("nightly", time.Minute, 0)
	res, _ := h.signedBeat("nightly", secret, strings.Repeat("6", 32), fixedNow.Unix())
	if res.StatusCode != http.StatusOK {
		t.Fatal(res.StatusCode)
	}
	// Move the clock a minute and a half past the beacon: the next sweep is what
	// turns an absence of traffic into a recorded event.
	later := fixedNow.Add(90 * time.Second)
	h.srv.SetClock(func() time.Time { return later })
	h.srv.sweep(context.Background())

	vs, err := h.srv.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].State != health.StateSilent {
		t.Fatalf("verdicts = %+v", vs)
	}
	as, err := h.st.RecentAlerts(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Kind != "silent" {
		t.Fatalf("alerts = %+v, want one silent event", as)
	}
	if !strings.Contains(h.logs.String(), "state transition") {
		t.Error("a transition should be logged")
	}

	// A beacon recovers it, and recovery is its own event.
	res, _ = h.signedBeat("nightly", secret, strings.Repeat("8", 32), later.Unix())
	if res.StatusCode != http.StatusOK {
		t.Fatalf("recovery beacon = %d", res.StatusCode)
	}
	vs, _ = h.srv.Status(context.Background())
	if vs[0].State != health.StateOK {
		t.Errorf("after recovery state = %s, want ok", vs[0].State)
	}
	if as, _ := h.st.RecentAlerts(context.Background(), 10); len(as) != 2 {
		t.Errorf("alerts = %+v, want silent then recovered", as)
	}
}

// One bad request must not take the collector down: the panic middleware answers
// 500, logs the stack and keeps serving.
func TestRecoverFromPanic(t *testing.T) {
	h := newHarness(t, nil)
	next := h.srv.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a panicking handler = %d, want 500", rec.Code)
	}
	if !strings.Contains(h.logs.String(), "panic recovered") {
		t.Errorf("the panic should be logged: %s", h.logs.String())
	}
	res, _ := h.get("/healthz", "")
	if res.StatusCode != http.StatusOK {
		t.Error("the server stopped serving after a panic")
	}
}

func TestMalformedPathIsHandled(t *testing.T) {
	h := newHarness(t, nil)
	req, err := http.NewRequest(http.MethodPost, "http://example.invalid/api/v1/beat/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Path = "/api/v1/beat/%zz"
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code == 0 {
		t.Error("a malformed escape produced no response")
	}
	if rec.Code >= 500 {
		t.Errorf("status = %d, want a client error", rec.Code)
	}
	res, _ := h.get("/healthz", "")
	if res.StatusCode != http.StatusOK {
		t.Error("the server stopped serving")
	}
}

func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
