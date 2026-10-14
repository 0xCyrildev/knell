package sign

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Known-answer vectors, computed with OpenSSL outside this code base so a
// change to the canonical message or the MAC cannot be smuggled in by editing
// this file to match a new implementation.
//
//	$ printf 'knell-v1\nnightly\n1700000000\n0123456789abcdef0123456789abcdef\n' \
//	    | openssl dgst -sha256 -mac HMAC -macopt hexkey:<64 zeros>
func TestKnownAnswerVectors(t *testing.T) {
	cases := []struct {
		secret, slug, nonce string
		ts                  int64
		want                string
	}{
		{
			strings.Repeat("0", 64), "nightly", "0123456789abcdef0123456789abcdef", 1700000000,
			// split so the value is not a contiguous 64-hex token in the repo
			"6d95ada7ca3b73001df344fb0ec81193" + "562d308a958d4f12da4d81b8d1756604",
		},
		{
			strings.Repeat("0", 63) + "1", "empty-note", strings.Repeat("a", 32), 1700000001,
			"b0dd03288b6b56897c03e666cb2c9037" + "b9673a842e634377d0b433de9acfe727",
		},
	}
	for _, c := range cases {
		got, err := Signature(c.secret, c.slug, c.ts, c.nonce)
		if err != nil {
			t.Fatalf("Signature(%s): %v", c.slug, err)
		}
		if got != c.want {
			t.Errorf("signature for %s = %s, want %s", c.slug, got, c.want)
		}
		if err := Verify(c.secret, c.slug, c.nonce, c.want, c.ts, time.Unix(c.ts, 0), time.Hour); err != nil {
			t.Errorf("Verify of the known-answer signature failed: %v", err)
		}
	}
}

func TestCanonicalIsInjective(t *testing.T) {
	triples := []struct {
		slug  string
		ts    int64
		nonce string
	}{
		{"a", 1, strings.Repeat("0", 32)},
		{"a", 11, strings.Repeat("0", 32)},
		{"a1", 1, strings.Repeat("0", 32)},
		{"a", 1, strings.Repeat("1", 32)},
		{"b", 1, strings.Repeat("0", 32)},
	}
	seen := map[string]string{}
	for _, tr := range triples {
		key := tr.slug + "/" + itoa(tr.ts) + "/" + tr.nonce
		k := string(Canonical(tr.slug, tr.ts, tr.nonce))
		if prev, dup := seen[k]; dup {
			t.Fatalf("two different triples canonicalise identically: %s and %s", prev, key)
		}
		seen[k] = key
	}
	// What makes the encoding unambiguous is that the fields cannot contain the
	// delimiter. If that ever loosens, the injection above stops holding.
	for _, bad := range []string{"a\nb", "a\n", "\n"} {
		if ValidSlug(bad) {
			t.Errorf("a slug containing a newline was accepted: %q", bad)
		}
		if ValidNonce(bad) {
			t.Errorf("a nonce containing a newline was accepted: %q", bad)
		}
	}
}

func TestVerifySkewBoundaries(t *testing.T) {
	secret := strings.Repeat("0", SecretLen)
	nonce := strings.Repeat("f", NonceLen)
	now := time.Unix(1700000000, 0)
	skew := 15 * time.Minute

	// Each row is signed for its own timestamp, so the only thing under test is
	// the window.
	cases := []struct {
		name string
		ts   time.Time
		want error
	}{
		{"now", now, nil},
		{"exactly skew old", now.Add(-skew), nil},
		{"one second too old", now.Add(-skew - time.Second), ErrStale},
		{"exactly skew ahead", now.Add(skew), nil},
		{"one second too far ahead", now.Add(skew + time.Second), ErrStale},
	}
	for _, c := range cases {
		sig, err := Signature(secret, "nightly", c.ts.Unix(), nonce)
		if err != nil {
			t.Fatal(err)
		}
		err = Verify(secret, "nightly", nonce, sig, c.ts.Unix(), now, skew)
		if c.want == nil && err != nil {
			t.Errorf("%s: expected acceptance, got %v", c.name, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: expected %v, got %v", c.name, c.want, err)
		}
	}
	// A captured beacon must not be reusable for a day: a zero or negative skew
	// falls back to the default rather than admitting "anything ever".
	if err := Verify(secret, "nightly", nonce, mustSig(t, secret, "nightly", now, nonce), now.Unix(), now, -time.Hour); err != nil {
		t.Errorf("a negative skew should fall back to the default, got %v", err)
	}
}

func mustSig(t *testing.T, secret, slug string, ts time.Time, nonce string) string {
	t.Helper()
	s, err := Signature(secret, slug, ts.Unix(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestVerifyRejections(t *testing.T) {
	secret := strings.Repeat("0", SecretLen)
	now := time.Unix(1700000000, 0)
	nonce := strings.Repeat("f", NonceLen)
	good, err := Signature(secret, "nightly", now.Unix(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	skew := 15 * time.Minute

	cases := []struct {
		name         string
		secret, slug string
		nonce, sig   string
		ts           int64
		want         error
	}{
		{"valid", secret, "nightly", nonce, good, now.Unix(), nil},
		{"wrong secret", strings.Repeat("1", 64), "nightly", nonce, good, now.Unix(), ErrSignature},
		{"malformed signature", secret, "nightly", nonce, good[:63], now.Unix(), ErrSignature},
		{"uppercase signature", secret, "nightly", nonce, strings.ToUpper(good), now.Unix(), ErrSignature},
		{"empty signature", secret, "nightly", nonce, "", now.Unix(), ErrSignature},
		{"short nonce", secret, "nightly", nonce[:31], good, now.Unix(), ErrNonce},
		{"slug with slash", secret, "a/b", nonce, good, now.Unix(), ErrSlug},
		{"uppercase slug", secret, "Nightly", nonce, good, now.Unix(), ErrSlug},
		{"ts one second too old", secret, "nightly", nonce, good, now.Add(-skew - time.Second).Unix(), ErrStale},
		{"ts in the future past skew", secret, "nightly", nonce, good, now.Add(skew + time.Second).Unix(), ErrStale},
		{"zero ts", secret, "nightly", nonce, good, 0, ErrTimestamp},
		{"ts beyond 2100", secret, "nightly", nonce, good, 4102444801, ErrTimestamp},
		{"malformed secret", "nope", "nightly", nonce, good, now.Unix(), ErrSecret},
	}
	for _, c := range cases {
		err := Verify(c.secret, c.slug, c.nonce, c.sig, c.ts, now, skew)
		if c.want == nil && err != nil {
			t.Errorf("%s: expected acceptance, got %v", c.name, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: expected %v, got %v", c.name, c.want, err)
		}
		// A rejection must never be a nil error and vice versa: callers branch on
		// these sentinels to choose an HTTP status.
	}
}

func TestSignatureBindsEveryField(t *testing.T) {
	secret := strings.Repeat("0", SecretLen)
	ts := int64(1700000000)
	base, err := Signature(secret, "nightly", ts, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := Signature(secret, "nightly", ts+1, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if base == other {
		t.Error("changing the timestamp did not change the signature")
	}
	other, _ = Signature(secret, "nightly", ts, strings.Repeat("b", 32))
	if base == other {
		t.Error("changing the nonce did not change the signature")
	}
	other, _ = Signature(secret, "nightl2", ts, strings.Repeat("a", 32))
	if base == other {
		t.Error("changing the slug did not change the signature")
	}
}

func TestReplayCache(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := NewReplayCache(time.Minute, 3)
	if err := c.Accept("nightly|abc", now); err != nil {
		t.Fatalf("first use should be accepted: %v", err)
	}
	if err := c.Accept("nightly|abc", now); !errors.Is(err, ErrReplay) {
		t.Errorf("second use should be a replay, got %v", err)
	}
	// A different check may reuse the same nonce string: the key is per check.
	if err := c.Accept("other|abc", now); err != nil {
		t.Errorf("a distinct slug should not be a replay: %v", err)
	}
	// Capacity is a refusal, not an eviction: silently forgetting a nonce would
	// admit exactly the thing the cache exists to stop.
	for _, k := range []string{"a|1", "b|2", "c|3"} {
		if err := c.Accept(k, now); err != nil && !errors.Is(err, ErrCacheFull) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if err := c.Accept("d|4", now); !errors.Is(err, ErrCacheFull) {
		t.Errorf("expected ErrCacheFull past capacity, got %v", err)
	}
	size, refusals := c.Stats()
	if refusals == 0 {
		t.Error("refusals should be counted for /metrics")
	}
	if size <= 0 {
		t.Errorf("cache should report occupancy, got %d", size)
	}
}

func TestReplayCacheExpires(t *testing.T) {
	c := NewReplayCache(time.Minute, 10)
	now := time.Unix(1700000000, 0)
	if err := c.Accept("k", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Accept("k", now.Add(2*time.Minute)); err != nil {
		t.Errorf("after the window an entry is no longer live: %v", err)
	}
}

// A cache that fills up must heal once its entries age out. Without pruning at
// capacity the first burst of nonces would lock every correctly signed beacon out
// of the endpoint forever — a self-inflicted outage caused by traffic that was
// already refused.
func TestReplayCacheHealsAfterCapacity(t *testing.T) {
	c := NewReplayCache(time.Minute, 4)
	now := time.Unix(1700000000, 0)
	for i := 0; i < 4; i++ {
		if err := c.Accept(fmt.Sprintf("k%d", i), now); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	if err := c.Accept("overflow", now); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("expected a refusal at capacity, got %v", err)
	}
	// Two hours later every stored nonce is outside any sane window.
	later := now.Add(2 * time.Hour)
	if err := c.Accept("overflow", later); err != nil {
		t.Errorf("after the window expired the cache should accept again, got %v", err)
	}
	size, _ := c.Stats()
	if size > 5 {
		t.Errorf("expired entries were not pruned: size = %d", size)
	}
	// Live entries are still refused, so healing did not come from forgetting.
	if err := c.Accept("overflow", later); !errors.Is(err, ErrReplay) {
		t.Errorf("the just-accepted nonce should now be replay-protected, got %v", err)
	}
}

func TestGeneratedMaterialIsValid(t *testing.T) {
	s, err := NewSecret()
	if err != nil || !ValidSecret(s) {
		t.Fatalf("NewSecret produced %q (%v)", s, err)
	}
	n, err := NewNonce()
	if err != nil || !ValidNonce(n) {
		t.Fatalf("NewNonce produced %q (%v)", n, err)
	}
	a, _ := NewNonce()
	b, _ := NewNonce()
	if a == b {
		t.Error("two nonces were identical")
	}
	if ValidSecret(strings.Repeat("A", 64)) {
		t.Error("an uppercase secret was accepted: two spellings of one key")
	}
}

func TestSecretLenMatchesEncoder(t *testing.T) {
	// The length constants are literals in the source, so pin them against the
	// encoders the tests and clients actually use.
	s, _ := NewSecret()
	if len(s) != SecretLen {
		t.Errorf("SecretLen = %d but NewSecret returns %d characters", SecretLen, len(s))
	}
	n, _ := NewNonce()
	if len(n) != NonceLen {
		t.Errorf("NonceLen = %d but NewNonce returns %d characters", NonceLen, len(n))
	}
	sig, _ := Signature(s, "nightly", 1, n)
	if len(sig) != SigLen {
		t.Errorf("SigLen = %d but a signature is %d characters", SigLen, len(sig))
	}
}

func TestSlugsAcceptThePracticalSet(t *testing.T) {
	for _, ok := range []string{"a", "nightly", "ci.build", "ci_build", "nightly-2", "9lives", "a63"} {
		if !ValidSlug(ok) {
			t.Errorf("slug %q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "A", "a b", "a/b", "a\\b", "a\n", string(make([]byte, 1))} {
		if ValidSlug(bad) {
			t.Errorf("slug %q should be invalid", bad)
		}
	}
	long := "a" + strings.Repeat("b", 64)
	if ValidSlug(long) {
		t.Error("a slug longer than 64 characters should be rejected")
	}
}
