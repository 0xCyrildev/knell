package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/0xCyrildev/knell/internal/sign"
)

// entry keeps the current secret and the one it replaced. A beacon signed
// before a rotation is still valid evidence about the past, so `knell verify`
// needs both keys to tell "rotated" apart from "tampered".
type entry struct {
	Secret   string `json:"secret"`
	Previous string `json:"previous,omitempty"`
}

// Keys holds signing secrets, one per check.
//
// They live in their own file rather than in the SQLite database on purpose:
// the database is what people back up, copy into issue attachments and mount
// into other containers. A leaked backup of checks and beacons should not be a
// leak of every key that can mint new beacons.
type Keys struct {
	mu   sync.RWMutex
	path string
	m    map[string]entry

	// reload is guarded separately from mu because a reader must be able to
	// refresh the map without holding the lock it would take to re-read it.
	reloadMu  sync.Mutex
	modTime   time.Time
	size      int64
	knownFile bool
	lastStat  time.Time
}

// ErrNoKey means a check exists but has never been given a signing secret.
var ErrNoKey = errors.New("no signing key for this check")

func OpenKeys(path string) (*Keys, error) {
	k := &Keys{path: path, m: map[string]entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("knell: reading keys: %w", err)
	}
	if len(b) == 0 {
		return k, nil
	}
	var doc struct {
		Version int              `json:"version"`
		Keys    map[string]entry `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("knell: parsing %s: %w", path, err)
	}
	if doc.Version > 1 {
		return nil, fmt.Errorf("knell: %s was written by a newer knell (version %d)", path, doc.Version)
	}
	for slug, e := range doc.Keys {
		if !sign.ValidSlug(slug) {
			return nil, fmt.Errorf("knell: %s contains an invalid slug %q", path, slug)
		}
		k.m[slug] = e
	}
	if err := k.harden(); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil {
		k.modTime, k.size, k.knownFile = fi.ModTime(), fi.Size(), true
	}
	return k, nil
}

// harden repairs permissions rather than refusing to start, because the common
// failure is a umask of 0022 on a file written by hand from cron.
func (k *Keys) harden() error {
	fi, err := os.Stat(k.path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(k.path, 0o600); err != nil {
		return fmt.Errorf("knell: %s is group/world readable and could not be tightened: %w", k.path, err)
	}
	return nil
}

func (k *Keys) Path() string { return k.path }

// refresh re-reads the keyring when another process — or a human with an editor
// and `knell add`/`knell rotate` — has changed the file since we last looked.
//
// Without this, a long-lived `knell serve` would reject every beacon for a check
// created after it started, and `knell rotate` could not revoke a leaked key
// without restarting the collector. Both are silent failures of the exact
// guarantee the product makes.
//
// It is best-effort by design: if the file vanishes mid-read we keep the keys we
// have rather than forgetting every secret because of a rename race.
func (k *Keys) refresh() {
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	now := time.Now()
	if !k.lastStat.IsZero() && now.Sub(k.lastStat) < time.Second {
		return
	}
	k.lastStat = now

	fi, err := os.Stat(k.path)
	if err != nil {
		k.knownFile = false
		return
	}
	k.mu.RLock()
	unchanged := k.knownFile && fi.ModTime().Equal(k.modTime) && fi.Size() == k.size
	k.mu.RUnlock()
	if unchanged {
		return
	}

	b, err := os.ReadFile(k.path)
	if err != nil {
		return
	}
	var doc struct {
		Version int              `json:"version"`
		Keys    map[string]entry `json:"keys"`
	}
	if len(b) > 0 && json.Unmarshal(b, &doc) != nil {
		return // a half-written file is not a reason to lose the live keys
	}
	if doc.Keys == nil {
		doc.Keys = map[string]entry{}
	}
	k.mu.Lock()
	k.m, k.modTime, k.size, k.knownFile = doc.Keys, fi.ModTime(), fi.Size(), true
	k.mu.Unlock()
}

func (k *Keys) Get(slug string) (string, error) {
	k.refresh()
	k.mu.RLock()
	defer k.mu.RUnlock()
	e := k.m[slug]
	if e.Secret == "" {
		return "", fmt.Errorf("%w: %s", ErrNoKey, slug)
	}
	return e.Secret, nil
}

// History returns the current key and, when one has been rotated away, the
// previous key. Beacons are immutable evidence, so verification must be able to
// account for a rotation without calling old beacons forged.
func (k *Keys) History(slug string) []string {
	k.refresh()
	k.mu.RLock()
	defer k.mu.RUnlock()
	e := k.m[slug]
	out := []string{}
	if e.Secret != "" {
		out = append(out, e.Secret)
	}
	if e.Previous != "" {
		out = append(out, e.Previous)
	}
	return out
}

func (k *Keys) Has(slug string) bool {
	k.refresh()
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.m[slug].Secret != ""
}

// Put stores a secret, generating one when secret is empty. The value that was
// stored before becomes the previous key. It returns the new secret so the
// caller can print it exactly once.
func (k *Keys) Put(slug, secret string) (string, error) {
	if !sign.ValidSlug(slug) {
		return "", sign.ErrSlug
	}
	if secret == "" {
		var err error
		if secret, err = newSecret(); err != nil {
			return "", err
		}
	} else if !sign.ValidSecret(secret) {
		return "", fmt.Errorf("knell: a signing key must be 64 lowercase hex characters")
	}
	k.mu.Lock()
	if secret == k.m[slug].Secret {
		k.mu.Unlock()
		return secret, nil
	}
	next := entry{Secret: secret, Previous: k.m[slug].Secret}
	k.m[slug] = next
	err := k.saveLocked()
	k.mu.Unlock()
	if err != nil {
		return "", err
	}
	return secret, nil
}

func (k *Keys) Delete(slug string) error {
	k.mu.Lock()
	_, ok := k.m[slug]
	delete(k.m, slug)
	err := k.saveLocked()
	k.mu.Unlock()
	if !ok {
		return nil
	}
	return err
}

// Fingerprints returns slug -> key id for the current key, for logs and status
// output. Only the fingerprint is ever printed.
func (k *Keys) Fingerprints() map[string]string {
	k.refresh()
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]string, len(k.m))
	for slug, e := range k.m {
		if e.Secret != "" {
			out[slug] = KeyID(e.Secret)
		}
	}
	return out
}

func (k *Keys) Slugs() []string {
	k.refresh()
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]string, 0, len(k.m))
	for slug := range k.m {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

// saveLocked writes atomically. Callers must hold k.mu.
func (k *Keys) saveLocked() error {
	if dir := filepath.Dir(k.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("knell: creating %s: %w", dir, err)
		}
	}
	doc := struct {
		Version int              `json:"version"`
		Keys    map[string]entry `json:"keys"`
	}{Version: 1, Keys: k.m}
	b, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(k.path), ".keys-*.tmp")
	if err != nil {
		return fmt.Errorf("knell: creating temp keys file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, k.path); err != nil {
		return fmt.Errorf("knell: replacing keys file: %w", err)
	}
	if d, err := os.Open(filepath.Dir(k.path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	// Remember what we just wrote, so refresh() does not re-read our own file a
	// moment later and mistake its own write for someone else's.
	if fi, err := os.Stat(k.path); err == nil {
		k.modTime, k.size, k.knownFile = fi.ModTime(), fi.Size(), true
	}
	return nil
}

func newSecret() (string, error) {
	b := make([]byte, sign.SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("knell: reading entropy: %w", err)
	}
	return hex.EncodeToString(b), nil
}
