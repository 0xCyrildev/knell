package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xCyrildev/knell/internal/health"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "knell.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func spec(slug string, period, grace time.Duration) Spec {
	return Spec{Slug: slug, Period: period, Grace: grace, Note: "test"}
}

func TestOpenMigratesAndRefusesANewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "knell.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != SchemaVersion {
		t.Errorf("user_version = %d, want %d", v, SchemaVersion)
	}
	s.Close()

	// Simulate a downgrade: a database from a future knell must be refused, not
	// read with assumptions.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path); !errors.Is(err, ErrUnsupported) {
		t.Errorf("reopening a newer database: got %v, want ErrUnsupported", err)
	}
}

func TestCheckLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.GetCheck(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown check: got %v, want ErrNotFound", err)
	}
	if err := s.AddCheck(ctx, spec("nightly", time.Hour, 5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCheck(ctx, spec("nightly", time.Hour, 0)); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate add: got %v, want ErrExists", err)
	}
	c, err := s.GetCheck(ctx, "nightly")
	if err != nil {
		t.Fatal(err)
	}
	if c.Last != nil {
		t.Error("a check with no beacons should have no last beacon")
	}
	if c.Period != time.Hour || c.Grace != 5*time.Minute || c.Note != "test" {
		t.Errorf("round-trip lost configuration: %+v", c)
	}
	if err := s.AddCheck(ctx, Spec{Slug: "zero", Period: 0}); err == nil {
		t.Error("a zero period should be refused: it would alert immediately and forever")
	}

	// Beacons are ordered by the claimed timestamp, not insertion order.
	old := time.Unix(1700000000, 0)
	newer := old.Add(time.Hour)
	if err := s.RecordBeacon(ctx, rec("nightly", newer.Unix(), "n2")); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBeacon(ctx, rec("nightly", old.Unix(), "n1")); err != nil {
		t.Fatal(err)
	}
	c, _ = s.GetCheck(ctx, "nightly")
	if c.Last == nil || c.Last.TS != newer.Unix() {
		t.Errorf("last beacon = %+v, want the newer one", c.Last)
	}
	if c.BeaconCount != 2 {
		t.Errorf("BeaconCount = %d, want 2", c.BeaconCount)
	}

	if err := s.RecordBeacon(ctx, rec("nightly", older(), "n1")); !errors.Is(err, ErrNonceUsed) {
		t.Errorf("replaying a nonce: got %v, want ErrNonceUsed", err)
	}
	if err := s.RecordBeacon(ctx, rec("elsewhere", older(), "n9")); !errors.Is(err, ErrNotFound) {
		t.Errorf("beacon for an unconfigured check: got %v, want ErrNotFound", err)
	}

	paused := true
	if err := s.UpdateCheck(ctx, "nightly", Patch{Paused: &paused, Note: strptr("maintenance")}); err != nil {
		t.Fatal(err)
	}
	c, _ = s.GetCheck(ctx, "nightly")
	if !c.Paused || c.Note != "maintenance" {
		t.Errorf("pause+note not stored: paused=%v note=%q", c.Paused, c.Note)
	}
	bad := time.Duration(0)
	if err := s.UpdateCheck(ctx, "nightly", Patch{Period: &bad}); err == nil {
		t.Error("a zero period via UpdateCheck should be refused")
	}
	if err := s.UpdateCheck(ctx, "ghost", Patch{Paused: &paused}); !errors.Is(err, ErrNotFound) {
		t.Errorf("updating a ghost: got %v, want ErrNotFound", err)
	}

	if _, err := s.LastAlert(ctx, "nightly", "silent"); !errors.Is(err, ErrNoAlerts) {
		t.Errorf("no alerts yet: got %v, want ErrNoAlerts", err)
	}
	if err := s.RecordAlert(ctx, Alert{Slug: "nightly", Kind: "silent", TS: older(), Detail: "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	a, err := s.LastAlert(ctx, "nightly", "silent")
	if err != nil || a.Detail != "gone quiet" {
		t.Errorf("LastAlert = %+v, %v", a, err)
	}

	if err := s.DeleteCheck(ctx, "nightly"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCheck(ctx, "nightly"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: got %v, want ErrNotFound", err)
	}
	counts, err := s.Counts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Beacons != 0 {
		t.Errorf("deleting a check left %d beacons behind; the history is theirs to keep only while the check exists", counts.Beacons)
	}
	if counts.Alerts != 0 {
		t.Errorf("deleting a check left %d alerts behind", counts.Alerts)
	}
}

func rec(slug string, ts int64, nonce string) health.Beacon {
	return health.Beacon{Slug: slug, TS: ts, ReceivedAt: ts, Nonce: nonce, Sig: "sig", Source: "test"}
}

func TestListChecksIsOrdered(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, slug := range []string{"zeta", "alpha", "mid"} {
		if err := s.AddCheck(ctx, spec(slug, time.Hour, 0)); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := s.ListChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "mid", "zeta"}
	for i, w := range want {
		if cs[i].Slug != w {
			t.Errorf("ListChecks order = %v, want %v", slugsOf(cs), want)
			break
		}
	}
	sl, err := s.Slugs(ctx)
	if err != nil || len(sl) != 3 {
		t.Errorf("Slugs = %v, %v", sl, err)
	}
}

func TestGCKeepsEvidenceForDeadChecks(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.AddCheck(ctx, spec("old", time.Hour, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCheck(ctx, spec("alive", time.Hour, 0)); err != nil {
		t.Fatal(err)
	}
	ancient := time.Now().Add(-100 * 24 * time.Hour).Unix()
	for i := int64(0); i < 10; i++ {
		if err := s.RecordBeacon(ctx, rec("old", ancient+i, nonceI(i))); err != nil {
			t.Fatal(err)
		}
	}
	fresh := time.Now().Unix()
	if err := s.RecordBeacon(ctx, rec("alive", fresh, "a1")); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAlert(ctx, Alert{Slug: "old", Kind: "silent", TS: ancient}); err != nil {
		t.Fatal(err)
	}

	rep, err := s.GC(ctx, GCOptions{KeepPerCheck: 3, MaxAge: 30 * 24 * time.Hour, AlertMaxAge: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if rep.BeaconsDeleted != 7 {
		t.Errorf("BeaconsDeleted = %d, want 7 (ten ancient, keep three)", rep.BeaconsDeleted)
	}
	if rep.AlertsDeleted != 1 {
		t.Errorf("AlertsDeleted = %d, want 1", rep.AlertsDeleted)
	}
	// The point of KeepPerCheck: a check that has been dead for months must not
	// silently switch from "silent since March" to "never reported".
	c, err := s.GetCheck(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if c.Last == nil || c.BeaconCount != 3 {
		t.Errorf("old check kept %+v (count %d), want 3 beacons and a last beacon", c.Last, c.BeaconCount)
	}
	if c2, _ := s.GetCheck(ctx, "alive"); c2.Last == nil {
		t.Error("a recent beacon must never be pruned")
	}
}

func TestGCDefaultsAreBounded(t *testing.T) {
	s := newStore(t)
	if _, err := s.GC(context.Background(), GCOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestKeysFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	k, err := OpenKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("opening a keyring should not create it: %v", err)
	}
	if _, err := k.Get("nightly"); !errors.Is(err, ErrNoKey) {
		t.Errorf("unknown slug: got %v, want ErrNoKey", err)
	}

	first, err := k.Put("nightly", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(path), "keys") {
		t.Fatal("path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("keyring mode = %O, must not be readable by group or other", fi.Mode().Perm())
	}
	// The generated secret must be usable as-is by the signer.
	if len(first) != 64 || strings.ToLower(first) != first {
		t.Errorf("generated key %q is not 64 lowercase hex characters", first)
	}

	again, err := k.Put("nightly", first)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Error("re-storing the same key changed it")
	}
	if h := k.History("nightly"); len(h) != 1 {
		t.Errorf("storing an identical key should not rotate history, got %d entries", len(h))
	}

	second, err := k.Put("nightly", "")
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Error("rotation produced the same key")
	}
	if got, _ := k.Get("nightly"); got != second {
		t.Error("Get should return the current key")
	}
	h := k.History("nightly")
	if len(h) != 2 || h[0] != second || h[1] != first {
		t.Errorf("History = %v, want [newest, previous]", h)
	}

	if fp := k.Fingerprints()["nightly"]; fp != KeyID(second) {
		t.Errorf("Fingerprints = %q, want the current key's id", fp)
	}
	if !k.Has("nightly") {
		t.Error("Has should be true")
	}

	// Survives a reopen, and leaves no temp files behind.
	k2, err := OpenKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k2.Get("nightly"); err != nil || got != second {
		t.Errorf("after reopen: %q, %v", got, err)
	}
	if h := k2.History("nightly"); len(h) != 2 {
		t.Errorf("rotation history did not survive a reopen: %v", h)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("atomic save left %s behind", e.Name())
		}
	}

	if err := k2.Delete("nightly"); err != nil {
		t.Fatal(err)
	}
	if _, err := k2.Get("nightly"); !errors.Is(err, ErrNoKey) {
		t.Errorf("after delete: %v", err)
	}
	if err := k2.Delete("never-existed"); err != nil {
		t.Errorf("deleting an unknown slug should be a no-op, got %v", err)
	}
}

func TestKeysRejectsMalformedInput(t *testing.T) {
	k, err := OpenKeys(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Put("Bad Slug", ""); err == nil {
		t.Error("an invalid slug should be refused")
	}
	if _, err := k.Put("ok", strings.Repeat("A", 64)); err == nil {
		t.Error("an uppercase key should be refused: it is a second spelling of one secret")
	}
	if _, err := k.Put("ok", "short"); err == nil {
		t.Error("a short key should be refused")
	}
	if _, err := k.Put("ok", strings.Repeat("0", 64)); err != nil {
		t.Errorf("a valid key was refused: %v", err)
	}
}

func TestKeyringRepairsPermissiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	body := `{"version":1,"keys":{"nightly":{"secret":"` + strings.Repeat("0", 64) + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	k, err := OpenKeys(path)
	if err != nil {
		t.Fatalf("a group-readable keyring should be tightened, not fatal: %v", err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("keyring is still %O after OpenKeys", fi.Mode().Perm())
	}
	if _, err := k.Get("nightly"); err != nil {
		t.Error(err)
	}
}

func TestKeyringRefusesAFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`{"version":7,"keys":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKeys(path); err == nil {
		t.Error("a keyring from a newer knell should be refused")
	}
}

// A collector is a long-lived process and `knell add` is not: if the keyring were
// read only at startup, every check created after the server started would reject
// its own beacons forever, and `knell rotate` could not revoke a leaked key
// without a restart. Both are silent failures of the product's one promise.
func TestKeyringPicksUpAnotherProcessWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	watcher, err := OpenKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := watcher.Put("first", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := watcher.Get("second"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("setup: %v", err)
	}

	other, err := OpenKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := other.Put("second", "")
	if err != nil {
		t.Fatal(err)
	}

	// The refresh is throttled to one stat per second so a busy collector does not
	// hammer the disk; wait out the window rather than pretending it is instant.
	time.Sleep(1100 * time.Millisecond)
	got, err := watcher.Get("second")
	if err != nil {
		t.Fatalf("the watcher did not see a key another process stored: %v", err)
	}
	if got != secret {
		t.Error("the watcher saw a different secret")
	}
	if !watcher.Has("second") {
		t.Error("Has should also see the new key")
	}
	if fp := watcher.Fingerprints()["second"]; fp != KeyID(secret) {
		t.Errorf("Fingerprints stale: %q", fp)
	}

	// Rotation must reach the watcher too: a leaked key is only revoked once the
	// process holding it stops accepting the old one.
	rotated, err := other.Put("second", "")
	if err != nil {
		t.Fatal(err)
	}
	if rotated == secret {
		t.Fatal("rotation produced the same key")
	}
	time.Sleep(1100 * time.Millisecond)
	hist := watcher.History("second")
	if len(hist) == 0 || hist[0] != rotated {
		t.Fatalf("current key after rotation = %q, want the rotated one", hist)
	}
}

func TestDatabaseFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "knell.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %O: checks, beacons and notes should not be readable by other local users",
				p, fi.Mode().Perm())
		}
	}
}

func TestKeyIDIsDomainSeparated(t *testing.T) {
	const secret = "0000000000000000000000000000000000000000000000000000000000000000"
	id := KeyID(secret)
	if len(id) != 12 {
		t.Errorf("key id %q is not 12 characters", id)
	}
	// A bare hash of the secret would let anyone holding a database dump run a
	// dictionary against stored key ids; the prefix is what this test pins.
	bare := sha256.Sum256([]byte(secret))
	if id == hex.EncodeToString(bare[:6]) {
		t.Error("KeyID is an undifferentiated hash of the secret")
	}
	if KeyID(secret) != id {
		t.Error("KeyID is not deterministic")
	}
	if KeyID(strings.Repeat("1", 64)) == id {
		t.Error("different secrets produced the same id")
	}
}

func older() int64 { return time.Now().Add(-time.Hour).Unix() }

func nonceI(i int64) string { return fmt.Sprintf("%032x", i) }

func strptr(s string) *string { return &s }

func slugsOf(cs []health.Check) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.Slug)
	}
	return out
}
