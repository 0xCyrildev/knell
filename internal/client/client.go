// Package client sends beacons: one signed HTTP POST, with the retries a job
// on flaky networking needs and without the retry loop that would hide an
// always-rejected signature.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0xCyrildev/knell/internal/sign"
)

const (
	// DefaultRetries and DefaultTimeout bound a beacon attempt: a check-in that
	// takes minutes to fail is worse than one that fails fast, because the
	// caller is usually a cron job with other work to do.
	DefaultRetries = 3
	DefaultTimeout = 10 * time.Second

	HeaderTimestamp = "Knell-Timestamp"
	HeaderNonce     = "Knell-Nonce"
	HeaderSignature = "Knell-Signature"
)

// ErrRedirect is returned instead of following a redirect, which would replay
// the signing headers onto whatever host the server points at.
var ErrRedirect = errors.New("knell: refusing to follow a redirect with signing headers")

type Target struct {
	URL       string // full beat URL, e.g. https://k.example/api/v1/beat/nightly
	Slug      string
	Secret    string
	Note      string
	Retries   int
	Timeout   time.Duration
	Now       func() time.Time
	Client    *http.Client
	UserAgent string
}

type Response struct {
	Status int
	State  string
	Reason string
	Body   map[string]any
}

// Beat signs and delivers one beacon. The returned error separates the two
// things an operator must tell apart: the network stumbled, or the server
// rejected the beacon on purpose.
func (t Target) Beat(ctx context.Context) (*Response, error) {
	if t.URL == "" {
		return nil, errors.New("knell: no server URL configured (set --url or base_url)")
	}
	if !sign.ValidSlug(t.Slug) {
		return nil, fmt.Errorf("%w: %q", sign.ErrSlug, t.Slug)
	}
	if !sign.ValidSecret(t.Secret) {
		return nil, fmt.Errorf("%w: a 64-character hex secret is required (see: knell token %s)", sign.ErrSecret, t.Slug)
	}
	now := t.nowFn()
	nonce, err := sign.NewNonce()
	if err != nil {
		return nil, err
	}
	sig, err := sign.Signature(t.Secret, t.Slug, now.Unix(), nonce)
	if err != nil {
		return nil, err
	}

	var payload []byte
	if t.Note != "" {
		b, err := json.Marshal(map[string]string{"note": t.Note})
		if err != nil {
			return nil, err
		}
		payload = b
	}

	retries := t.Retries
	if retries <= 0 {
		retries = DefaultRetries
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	hc := t.Client
	if hc == nil {
		hc = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          4,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				ResponseHeaderTimeout: timeout,
			},
		}
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, backoff(attempt)); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("knell: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		ua := t.UserAgent
		if ua == "" {
			ua = "knell-beacon"
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderSignature, sig)

		res, err := hc.Do(req)
		if errors.Is(err, ErrRedirect) {
			return nil, err
		}
		if err != nil {
			lastErr = err
			continue // transport failure: worth another try
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		text := strings.TrimSpace(string(body))
		resp := &Response{Status: res.StatusCode, Body: map[string]any{}}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &resp.Body); err != nil {
				resp.Reason = text
			}
		}
		resp.State = str(resp.Body["state"])
		resp.Reason = firstNonEmpty(str(resp.Body["reason"]), resp.Reason)

		switch {
		case res.StatusCode >= 200 && res.StatusCode < 300:
			return resp, nil
		case res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusRequestTimeout:
			if d := retryAfter(res); d > 0 {
				if err := sleep(ctx, d); err != nil {
					return resp, err
				}
			}
			lastErr = fmt.Errorf("knell: server returned %d: %s", res.StatusCode, text)
		case res.StatusCode >= 500:
			lastErr = fmt.Errorf("knell: server returned %d: %s", res.StatusCode, text)
		default:
			// Any other 4xx is a verdict, not a stumble: a bad signature or a
			// clock outside the skew window fails identically on every retry.
			return resp, fmt.Errorf("knell: rejected (%d): %s", res.StatusCode,
				firstNonEmpty(resp.Reason, text))
		}
	}
	return nil, fmt.Errorf("knell: giving up after %d attempt(s): %w", retries, lastErr)
}

// Headers returns the signing headers as a map, which is what `knell sign`
// prints so an operator can exercise a check with curl alone.
func Headers(secret, slug string, ts time.Time, nonce string) (map[string]string, error) {
	sig, err := sign.Signature(secret, slug, ts.Unix(), nonce)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		HeaderTimestamp: strconv.FormatInt(ts.Unix(), 10),
		HeaderNonce:     nonce,
		HeaderSignature: sig,
	}, nil
}

func retryAfter(res *http.Response) time.Duration {
	v := res.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 && secs <= 60 {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 && d <= time.Minute {
			return d
		}
	}
	return 0
}

func (t Target) nowFn() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// backoff grows to about 10s so a short-lived outage is ridden out, while the
// total stay inside the caller's own deadline.
func backoff(attempt int) time.Duration {
	base := time.Duration(1<<min(attempt, 5)) * 300 * time.Millisecond
	jit, err := rand.Int(rand.Reader, big.NewInt(200))
	if err != nil {
		return base
	}
	return base + time.Duration(jit.Int64())*time.Millisecond
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
