// Package store persists checks, beacons and alert events in a single SQLite
// file, and signing secrets in a separate 0600 file.
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
	"time"

	"github.com/0xCyrildev/knell/internal/health"

	_ "modernc.org/sqlite"
)

// SchemaVersion is stored in PRAGMA user_version so a future release can
// detect a database written by an older or newer knell instead of misreading it.
const SchemaVersion = 1

var (
	ErrNotFound    = errors.New("check not found")
	ErrExists      = errors.New("check already exists")
	ErrNonceUsed   = errors.New("beacon nonce already recorded")
	ErrNoBeacons   = errors.New("no beacons recorded")
	ErrNoAlerts    = errors.New("no alert events recorded")
	ErrUnsupported = errors.New("database was written by an unsupported knell version")
)

type Store struct {
	db   *sql.DB
	path string
}

func (s *Store) Path() string { return s.path }

// Open creates the database if needed and applies the schema. WAL plus a
// busy timeout lets `knell beat` write while `knell serve` reads on the same
// file; writers are serialised by a single open connection.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		// 0700, not 0755: this directory holds the state file whose contents
		// `knell verify` is meant to be able to vouch for.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("knell: creating %s: %w", dir, err)
		}
	}
	dsn := "file:" + filepath.Clean(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("knell: opening database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(0)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("knell: opening %s: %w", path, err)
	}
	s := &Store{db: db, path: path}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	// SQLite creates the file from the process umask, which under cron is often
	// 0022 — that would leave every check, beacon and note readable by any local
	// user while knell's own report implies this state is private to its owner.
	s.hardenFiles()
	return s, nil
}

// hardenFiles restricts the database and its WAL sidecars to the owner. It is
// best-effort: a read-only filesystem or a foreign owner must not stop a check
// that is already running.
func (s *Store) hardenFiles() {
	for _, p := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(p, 0o600)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return fmt.Errorf("knell: reading schema version: %w", err)
	}
	if v > SchemaVersion {
		return fmt.Errorf("%w: found schema %d, this knell understands %d", ErrUnsupported, v, SchemaVersion)
	}
	if v == SchemaVersion {
		return nil
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS checks (
	slug           TEXT PRIMARY KEY,
	period_seconds INTEGER NOT NULL CHECK (period_seconds > 0),
	grace_seconds  INTEGER NOT NULL DEFAULT 0 CHECK (grace_seconds >= 0),
	note           TEXT NOT NULL DEFAULT '',
	paused         INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	key_id         TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS beacons (
	id         INTEGER PRIMARY KEY,
	slug       TEXT NOT NULL REFERENCES checks(slug) ON DELETE CASCADE,
	ts         INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	source     TEXT NOT NULL DEFAULT 'local',
	nonce      TEXT NOT NULL,
	sig        TEXT NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	UNIQUE (slug, nonce)
);
CREATE INDEX IF NOT EXISTS beacons_slug_ts ON beacons (slug, ts DESC);
CREATE TABLE IF NOT EXISTS alerts (
	id     INTEGER PRIMARY KEY,
	slug   TEXT NOT NULL,
	kind   TEXT NOT NULL,
	ts     INTEGER NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_slug_ts ON alerts (slug, ts DESC);
`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("knell: applying schema: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion)); err != nil {
		return fmt.Errorf("knell: recording schema version: %w", err)
	}
	return nil
}

type Spec struct {
	Slug   string
	Period time.Duration
	Grace  time.Duration
	Note   string
	KeyID  string
}

func (s *Store) AddCheck(ctx context.Context, in Spec) error {
	if in.Period <= 0 {
		return fmt.Errorf("knell: period must be positive")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO checks (slug, period_seconds, grace_seconds, note, paused, created_at, key_id)
		 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6) ON CONFLICT (slug) DO NOTHING`,
		in.Slug, int64(in.Period/time.Second), int64(in.Grace/time.Second), in.Note, time.Now().Unix(), in.KeyID)
	if err != nil {
		return classify(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrExists
	}
	return nil
}

func (s *Store) DeleteCheck(ctx context.Context, slug string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM checks WHERE slug = ?1`, slug)
	if err != nil {
		return classify(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM beacons WHERE slug = ?1`, slug)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM alerts WHERE slug = ?1`, slug)
	return nil
}

type Patch struct {
	Period *time.Duration
	Grace  *time.Duration
	Note   *string
	Paused *bool
	KeyID  *string
}

func (s *Store) UpdateCheck(ctx context.Context, slug string, p Patch) error {
	sets := []string{}
	args := []any{}
	add := func(clause string, v any) {
		sets = append(sets, clause)
		args = append(args, v)
	}
	if p.Period != nil {
		if *p.Period <= 0 {
			return fmt.Errorf("knell: period must be positive")
		}
		add("period_seconds = ?", int64(*p.Period/time.Second))
	}
	if p.Grace != nil {
		if *p.Grace < 0 {
			return fmt.Errorf("knell: grace must not be negative")
		}
		add("grace_seconds = ?", int64(*p.Grace/time.Second))
	}
	if p.Note != nil {
		add("note = ?", *p.Note)
	}
	if p.Paused != nil {
		add("paused = ?", boolInt(*p.Paused))
	}
	if p.KeyID != nil {
		add("key_id = ?", *p.KeyID)
	}
	if len(sets) == 0 {
		return ErrNotFound
	}
	args = append(args, slug)
	q := `UPDATE checks SET ` + strings.Join(sets, ", ") + ` WHERE slug = ?`
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return classify(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanCheck(row interface{ Scan(...any) error }) (health.Check, error) {
	var (
		c             health.Check
		period, grace int64
		paused        int
		created       int64
		count         int64
	)
	err := row.Scan(&c.Slug, &period, &grace, &c.Note, &paused, &created, &count)
	if err != nil {
		return health.Check{}, err
	}
	c.Period, c.Grace = time.Duration(period)*time.Second, time.Duration(grace)*time.Second
	c.Paused = paused != 0
	c.CreatedAt = time.Unix(created, 0)
	c.BeaconCount = count
	return c, nil
}

const checkSelect = `
SELECT c.slug, c.period_seconds, c.grace_seconds, c.note, c.paused, c.created_at,
       (SELECT count(*) FROM beacons b WHERE b.slug = c.slug)
FROM checks c`

func (s *Store) GetCheck(ctx context.Context, slug string) (health.Check, error) {
	c, err := scanCheck(s.db.QueryRowContext(ctx, checkSelect+` WHERE c.slug = ?1`, slug))
	if errors.Is(err, sql.ErrNoRows) {
		return health.Check{}, ErrNotFound
	}
	if err != nil {
		return health.Check{}, classify(err)
	}
	if last, err := s.LastBeacon(ctx, slug); err == nil {
		c.Last = &last
	} else if !errors.Is(err, ErrNoBeacons) {
		return health.Check{}, err
	}
	return c, nil
}

func (s *Store) ListChecks(ctx context.Context) ([]health.Check, error) {
	rows, err := s.db.QueryContext(ctx, checkSelect+` ORDER BY c.slug`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []health.Check{}
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, classify(err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if last, err := s.LastBeacon(ctx, out[i].Slug); err == nil {
			out[i].Last = &last
		} else if !errors.Is(err, ErrNoBeacons) {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) RecordBeacon(ctx context.Context, b health.Beacon) error {
	if b.ReceivedAt == 0 {
		b.ReceivedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO beacons (slug, ts, received_at, source, nonce, sig, note) VALUES (?1,?2,?3,?4,?5,?6,?7)`,
		b.Slug, b.TS, b.ReceivedAt, orDefault(b.Source, "local"), b.Nonce, b.Sig, b.Note)
	if err != nil {
		if isUnique(err) {
			return ErrNonceUsed
		}
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			return ErrNotFound
		}
		return classify(err)
	}
	return nil
}

func (s *Store) LastBeacon(ctx context.Context, slug string) (health.Beacon, error) {
	b, err := scanBeacon(s.db.QueryRowContext(ctx, beaconSelect+` WHERE slug = ?1 ORDER BY ts DESC, id DESC LIMIT 1`, slug))
	if errors.Is(err, sql.ErrNoRows) {
		return health.Beacon{}, ErrNoBeacons
	}
	return b, classify(err)
}

const beaconSelect = `SELECT slug, ts, received_at, source, nonce, sig, note FROM beacons`

func (s *Store) RecentBeacons(ctx context.Context, slug string, limit int) ([]health.Beacon, error) {
	if limit <= 0 || limit > 1000 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, beaconSelect+` WHERE slug = ?1 ORDER BY ts DESC, id DESC LIMIT ?2`, slug, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []health.Beacon{}
	for rows.Next() {
		b, err := scanBeacon(rows)
		if err != nil {
			return nil, classify(err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanBeacon(row interface{ Scan(...any) error }) (health.Beacon, error) {
	var b health.Beacon
	err := row.Scan(&b.Slug, &b.TS, &b.ReceivedAt, &b.Source, &b.Nonce, &b.Sig, &b.Note)
	return b, err
}

type Alert struct {
	Slug   string
	Kind   string
	TS     int64
	Detail string
}

func (s *Store) RecordAlert(ctx context.Context, a Alert) error {
	if a.TS == 0 {
		a.TS = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO alerts (slug, kind, ts, detail) VALUES (?1,?2,?3,?4)`,
		a.Slug, a.Kind, a.TS, a.Detail)
	return classify(err)
}

// LastAlert returns the most recent event of kind for a slug, which is what
// tells a report *when* something went quiet rather than only that it did.
func (s *Store) LastAlert(ctx context.Context, slug, kind string) (Alert, error) {
	var a Alert
	err := s.db.QueryRowContext(ctx,
		`SELECT slug, kind, ts, detail FROM alerts WHERE slug = ?1 AND kind = ?2 ORDER BY ts DESC, id DESC LIMIT 1`,
		slug, kind).Scan(&a.Slug, &a.Kind, &a.TS, &a.Detail)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, ErrNoAlerts
	}
	return a, classify(err)
}

func (s *Store) RecentAlerts(ctx context.Context, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT slug, kind, ts, detail FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1`, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.Slug, &a.Kind, &a.TS, &a.Detail); err != nil {
			return nil, classify(err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type GCOptions struct {
	KeepPerCheck int           // newest beacons always kept
	MaxAge       time.Duration // beacons older than this are eligible
	AlertMaxAge  time.Duration
}

type GCReport struct {
	BeaconsDeleted int64 `json:"beacons_deleted"`
	AlertsDeleted  int64 `json:"alerts_deleted"`
	// Warning names a step that did not fail the prune but that an operator should
	// see: a refused WAL checkpoint means the -wal file will keep growing.
	Warning string `json:"warning,omitempty"`
}

// GC bounds history. It protects a check whose beacons are all old: without
// KeepPerCheck a long-dead but still-configured check would lose its evidence
// and start reporting "never".
func (s *Store) GC(ctx context.Context, o GCOptions) (GCReport, error) {
	if o.KeepPerCheck <= 0 {
		o.KeepPerCheck = 50
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 30 * 24 * time.Hour
	}
	if o.AlertMaxAge <= 0 {
		o.AlertMaxAge = 90 * 24 * time.Hour
	}
	cutoff := time.Now().Add(-o.MaxAge).Unix()
	// `<=` on purpose: timestamps are whole seconds here, so a strict `<` would
	// make `--max-age 1ns` prune nothing at all, which is the opposite of what an
	// operator asking to trim history means.
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM beacons WHERE ts <= ?1 AND id NOT IN (
		   SELECT id FROM (SELECT b.id AS id,
				      row_number() OVER (PARTITION BY b.slug ORDER BY b.ts DESC, b.id DESC) AS n
				 FROM beacons b) WHERE n <= ?2)`,
		cutoff, o.KeepPerCheck)
	if err != nil {
		return GCReport{}, classify(err)
	}
	rep := GCReport{}
	rep.BeaconsDeleted, _ = res.RowsAffected()
	cutAlert := time.Now().Add(-o.AlertMaxAge).Unix()
	res, err = s.db.ExecContext(ctx, `DELETE FROM alerts WHERE ts <= ?1`, cutAlert)
	if err != nil {
		return rep, classify(err)
	}
	rep.AlertsDeleted, _ = res.RowsAffected()
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		rep.Warning = fmt.Sprintf("WAL checkpoint refused (%v): the -wal file will grow until a writer can truncate it", err)
	}
	return rep, nil
}

type Counts struct {
	Checks  int64 `json:"checks"`
	Beacons int64 `json:"beacons"`
	Alerts  int64 `json:"alerts"`
}

func (s *Store) Counts(ctx context.Context) (Counts, error) {
	var c Counts
	err := s.db.QueryRowContext(ctx,
		`SELECT (SELECT count(*) FROM checks), (SELECT count(*) FROM beacons), (SELECT count(*) FROM alerts)`).
		Scan(&c.Checks, &c.Beacons, &c.Alerts)
	return c, classify(err)
}

// Slugs lists configured checks without loading their beacons.
func (s *Store) Slugs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT slug FROM checks ORDER BY slug`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, classify(err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExists) {
		return err
	}
	return fmt.Errorf("knell: %w", err)
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// KeyID fingerprints a secret for logs and CLI output. The fingerprint is not
// a hash of the secret alone: it is domain-separated so a stored key_id cannot
// be attacked with a precomputed dictionary of raw secrets.
func KeyID(secret string) string {
	sum := sha256.Sum256([]byte("knell-keyid-v1\n" + secret))
	return hex.EncodeToString(sum[:6])
}
