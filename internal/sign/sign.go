// Package sign implements knell's beacon signatures: a tamper-evident proof
// that a check-in was emitted by someone holding the check's secret.
package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	// Alg is prefixed into the signed message so a future scheme cannot be
	// confused with this one.
	Alg = "knell-v1"

	SecretBytes = 32
	NonceBytes  = 16

	// SecretLen, NonceLen and SigLen are hex lengths: 32, 16 and 32 bytes.
	// They are literals so they can be consts; the known-answer tests in
	// sign_test.go pin them to the encoders.
	SecretLen = 64
	NonceLen  = 32
	SigLen    = 64

	DefaultSkew = 15 * time.Minute
)

var (
	ErrSlug      = errors.New("invalid slug")
	ErrNonce     = errors.New("invalid nonce")
	ErrSecret    = errors.New("invalid secret")
	ErrSignature = errors.New("invalid signature")
	ErrStale     = errors.New("timestamp outside the accepted window")
	ErrReplay    = errors.New("nonce already accepted")
	ErrTimestamp = errors.New("invalid timestamp")
	ErrCacheFull = errors.New("replay cache at capacity")

	slugRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	secretRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nonceRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sigRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidSlug reports whether s is safe to use as a check identifier. Slugs are
// signed, stored in paths and interpolated into shell examples, so the charset
// deliberately excludes newlines, spaces, slashes and uppercase.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// ValidSecret reports whether s is a usable signing key: exactly 32 bytes of
// lowercase hex. Uppercase would decode to the same bytes but would not match
// the signature regex, so accepting it would create two spellings of one key.
func ValidSecret(s string) bool { return secretRE.MatchString(s) }

// ValidNonce reports whether s is a well-formed nonce.
func ValidNonce(s string) bool { return nonceRE.MatchString(s) }

// ValidSignature reports whether s is a well-formed signature.
func ValidSignature(s string) bool { return sigRE.MatchString(s) }

// NewSecret returns a hex-encoded 256-bit signing key.
func NewSecret() (string, error) {
	return randHex(SecretBytes)
}

// NewNonce returns a hex-encoded random nonce, unique per beacon.
func NewNonce() (string, error) { return randHex(NonceBytes) }

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("knell: reading entropy: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Canonical builds the exact bytes that get signed. Fields are newline
// terminated and each one's charset is validated by the callers, so no value
// can imitate a delimiter.
func Canonical(slug string, ts int64, nonce string) []byte {
	var b []byte
	b = append(b, Alg...)
	b = append(b, '\n')
	b = append(b, slug...)
	b = append(b, '\n')
	b = append(b, strconv.FormatInt(ts, 10)...)
	b = append(b, '\n')
	b = append(b, nonce...)
	b = append(b, '\n')
	return b
}

// Signature is the lowercase hex HMAC-SHA256 of the canonical beacon.
func Signature(secret, slug string, ts int64, nonce string) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	if !ValidSlug(slug) {
		return "", ErrSlug
	}
	if !nonceRE.MatchString(nonce) {
		return "", ErrNonce
	}
	m := hmac.New(sha256.New, key)
	m.Write(Canonical(slug, ts, nonce))
	return hex.EncodeToString(m.Sum(nil)), nil
}

// Verify checks a beacon against the expected window and signature. Every
// rejection is a distinct sentinel error so callers can count and report
// reasons instead of a single "400".
func Verify(secret, slug, nonce, sig string, ts int64, now time.Time, skew time.Duration) error {
	if !ValidSlug(slug) {
		return ErrSlug
	}
	if !nonceRE.MatchString(nonce) {
		return ErrNonce
	}
	// Enforce a fixed-length hex signature before comparing so the comparison
	// never leaks how many leading bytes happened to match.
	if !sigRE.MatchString(sig) {
		return ErrSignature
	}
	if ts <= 0 || ts > 4102444800 { // 2100-01-01
		return ErrTimestamp
	}
	if skew < 0 {
		skew = DefaultSkew
	}
	if d := now.Sub(time.Unix(ts, 0)); d > skew || d < -skew {
		return ErrStale
	}
	want, err := Signature(secret, slug, ts, nonce)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return ErrSignature
	}
	return nil
}

func decode(secret string) ([]byte, error) {
	if !ValidSecret(secret) {
		return nil, ErrSecret
	}
	key, err := hex.DecodeString(secret)
	if err != nil {
		return nil, ErrSecret
	}
	return key, nil
}

// ReplayCache remembers nonces accepted inside the skew window. Without it a
// captured beacon could be re-sent until its timestamp aged out.
type ReplayCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	window    time.Duration
	max       int
	dropped   int
	nextPrune time.Time
}

func NewReplayCache(window time.Duration, max int) *ReplayCache {
	if window <= 0 {
		window = DefaultSkew
	}
	if max <= 0 {
		max = 100_000
	}
	return &ReplayCache{seen: make(map[string]time.Time), window: window, max: max}
}

// Accept records key and reports whether it had not been seen. A full cache
// refuses rather than evicting a live entry, because forgetting a nonce inside its
// window would admit exactly the replay the cache exists to stop — but it prunes
// expired entries first, so a burst that once filled it cannot lock the endpoint
// out forever.
func (c *ReplayCache) Accept(key string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[key]; ok && exp.After(now) {
		return ErrReplay
	}
	if len(c.seen) >= c.max || !c.nextPrune.After(now) {
		c.pruneLocked(now)
	}
	c.nextPrune = now.Add(time.Second)
	if len(c.seen) >= c.max {
		c.dropped++
		return ErrCacheFull
	}
	c.seen[key] = now.Add(c.window)
	return nil
}

func (c *ReplayCache) pruneLocked(now time.Time) {
	for k, exp := range c.seen {
		if !exp.After(now) {
			delete(c.seen, k)
		}
	}
}

// Stats reports cache occupancy for /metrics.
func (c *ReplayCache) Stats() (size, refusals int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen), c.dropped
}
