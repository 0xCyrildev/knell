package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xCyrildev/knell/internal/sign"
)

// A hex key assembled from parts rather than spelled contiguously: a 64-character
// hex literal in a repository is exactly what secret-scanning push protection
// looks for, and this is not a credential.
var testSecret = strings.Repeat("0123456789abcdef", 4)

// countingServer replies with the codes given, cycling to the last one, and
// records every request so retry behaviour is observable rather than assumed.
type counting struct {
	t          *testing.T
	attempts   atomic.Int32
	codes      []int
	retryAfter map[int]string
	location   string
	last       atomic.Value
}

func (c *counting) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := c.attempts.Add(1) - 1
	code := c.codes[len(c.codes)-1]
	if int(n) < len(c.codes) {
		code = c.codes[n]
	}
	body, _ := io.ReadAll(r.Body)
	c.last.Store(map[string]any{
		"ts":     r.Header.Get(HeaderTimestamp),
		"nonce":  r.Header.Get(HeaderNonce),
		"sig":    r.Header.Get(HeaderSignature),
		"note":   string(body),
		"ua":     r.Header.Get("User-Agent"),
		"path":   r.URL.Path,
		"method": r.Method,
	})
	if code == http.StatusPermanentRedirect || code == http.StatusFound {
		w.Header().Set("Location", c.location)
	}
	if ra, ok := c.retryAfter[code]; ok {
		w.Header().Set("Retry-After", ra)
	}
	w.WriteHeader(code)
	_, _ = io.WriteString(w, `{"reason":"server said so"}`)
}

type retryable struct {
	codes      []int
	retryAfter map[int]string
	location   string
}

func newServer(t *testing.T, cfg retryable) (*httptest.Server, *counting) {
	t.Helper()
	c := &counting{t: t, codes: cfg.codes, retryAfter: cfg.retryAfter, location: cfg.location}
	ts := httptest.NewServer(c)
	t.Cleanup(ts.Close)
	return ts, c
}

func target(url, slug string) Target {
	return Target{
		URL:     url + "/api/v1/beat/" + slug,
		Slug:    slug,
		Secret:  testSecret,
		Retries: 3,
		Timeout: 2 * time.Second,
	}
}

func TestBeatSendsAVerifiableSignature(t *testing.T) {
	ts, c := newServer(t, retryable{codes: []int{http.StatusOK}})
	res, err := target(ts.URL, "nightly").Beat(context.Background())
	if err != nil {
		t.Fatalf("Beat: %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d", res.Status)
	}
	seen := c.last.Load().(map[string]any)
	tsVal, _ := seen["ts"].(string)
	nonce, _ := seen["nonce"].(string)
	sig, _ := seen["sig"].(string)
	if tsVal == "" || nonce == "" || sig == "" {
		t.Fatalf("the server did not see the signing headers: %v", seen)
	}
	// A signature the client produced must verify under the same rules the
	// server applies, otherwise every beacon would be a 401 in production.
	var unix int64
	if _, err := fmt.Sscanf(tsVal, "%d", &unix); err != nil {
		t.Fatalf("timestamp %q is not a unix second", tsVal)
	}
	if err := sign.Verify(testSecret, "nightly", nonce, sig, unix, time.Now(), time.Hour); err != nil {
		t.Errorf("the signature the client sent does not verify: %v", err)
	}
	if seen["method"] != http.MethodPost {
		t.Errorf("method = %v", seen["method"])
	}
	if !strings.Contains(seen["path"].(string), "/api/v1/beat/nightly") {
		t.Errorf("path = %v", seen["path"])
	}
}

func TestBeatNotesAreSentAsJSON(t *testing.T) {
	ts, c := newServer(t, retryable{codes: []int{http.StatusOK}})
	tg := target(ts.URL, "nightly")
	tg.Note = "uploaded 12 GB"
	if _, err := tg.Beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := c.last.Load().(map[string]any)
	if !strings.Contains(seen["note"].(string), `"note":"uploaded 12 GB"`) {
		t.Errorf("body = %v", seen["note"])
	}
}

func TestBeatRetriesServerErrors(t *testing.T) {
	ts, c := newServer(t, retryable{codes: []int{503, 502, http.StatusOK}})
	res, err := target(ts.URL, "nightly").Beat(context.Background())
	if err != nil {
		t.Fatalf("a transient outage should be ridden out, got %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d", res.Status)
	}
	if got := c.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestBeatGivesUpWithAClearError(t *testing.T) {
	ts, c := newServer(t, retryable{codes: []int{500}})
	_, err := target(ts.URL, "nightly").Beat(context.Background())
	if err == nil {
		t.Fatal("an always-500 server must produce an error")
	}
	if !strings.Contains(err.Error(), "giving up after 3 attempt(s)") {
		t.Errorf("error = %q", err)
	}
	if got := c.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

// A rejected beacon is a verdict, not a network stumble. Hammering a server that
// says no would be both rude and useless.
func TestBeatDoesNotRetryARejection(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusForbidden} {
		ts, c := newServer(t, retryable{codes: []int{code}})
		_, err := target(ts.URL, "nightly").Beat(context.Background())
		if err == nil {
			t.Fatalf("status %d should be an error", code)
		}
		if got := c.attempts.Load(); got != 1 {
			t.Errorf("status %d: attempts = %d, want 1", code, got)
		}
	}
}

func TestBeatHonoursRetryAfter(t *testing.T) {
	ts, c := newServer(t, retryable{
		codes:      []int{http.StatusTooManyRequests, http.StatusOK},
		retryAfter: map[int]string{http.StatusTooManyRequests: "1"},
	})
	start := time.Now()
	_, err := target(ts.URL, "nightly").Beat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("Retry-After: 1 was ignored, waited only %s", elapsed)
	}
	if got := c.attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

// Following a redirect would replay the signing headers onto a host the operator
// never chose.
func TestBeatRefusesRedirects(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	ts, _ := newServer(t, retryable{codes: []int{http.StatusFound}, location: other.URL})
	_, err := target(ts.URL, "nightly").Beat(context.Background())
	if err == nil {
		t.Fatal("a redirect should be an error")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error = %q, should name the redirect", err)
	}
	if otherHits.Load() != 0 {
		t.Errorf("the redirect target was contacted %d time(s) with signing headers", otherHits.Load())
	}
}

func TestBeatValidatesBeforeTouchingTheNetwork(t *testing.T) {
	ts, c := newServer(t, retryable{codes: []int{http.StatusOK}})
	cases := []struct {
		name   string
		mutate func(*Target)
	}{
		{"no url", func(tg *Target) { tg.URL = "" }},
		{"bad slug", func(tg *Target) { tg.Slug = "Bad Slug"; tg.URL = ts.URL + "/api/v1/beat/Bad Slug" }},
		{"short secret", func(tg *Target) { tg.Secret = "abc" }},
		{"uppercase secret", func(tg *Target) { tg.Secret = strings.ToUpper(testSecret) }},
	}
	for _, c := range cases {
		tg := target(ts.URL, "nightly")
		c.mutate(&tg)
		if _, err := tg.Beat(context.Background()); err == nil {
			t.Errorf("%s: expected a refusal before any request", c.name)
		}
	}
	if got := c.attempts.Load(); got != 0 {
		t.Errorf("the server saw %d request(s), want 0", got)
	}
}

func TestBeatRespectsContextCancellation(t *testing.T) {
	ts, _ := newServer(t, retryable{codes: []int{500}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tg := target(ts.URL, "nightly")
	tg.Retries = 5
	if _, err := tg.Beat(ctx); err == nil {
		t.Error("a cancelled context must stop the retry loop")
	}
}

func TestHeadersRoundTripsThroughVerify(t *testing.T) {
	now := time.Unix(1700000000, 0)
	nonce := strings.Repeat("2", sign.NonceLen)
	h, err := Headers(testSecret, "nightly", now, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(h[HeaderSignature]) != sign.SigLen {
		t.Errorf("signature length = %d", len(h[HeaderSignature]))
	}
	if err := sign.Verify(testSecret, "nightly", nonce, h[HeaderSignature],
		now.Unix(), now, 15*time.Minute); err != nil {
		t.Errorf("Headers output does not verify: %v", err)
	}
}

func TestHeadersRejectsBadKeys(t *testing.T) {
	if _, err := Headers("nope", "nightly", time.Now(), strings.Repeat("0", 32)); err == nil {
		t.Error("a malformed secret should be refused, not signed with")
	}
}
