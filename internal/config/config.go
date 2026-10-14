// Package config loads knell settings from a JSON file, the environment and
// flags, in that order of increasing precedence.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	DBPath    string `json:"db_path"`
	KeysPath  string `json:"keys_path"`
	Listen    string `json:"listen"`
	BaseURL   string `json:"base_url"`
	Skew      Dur    `json:"skew"`
	EvalEvery Dur    `json:"eval_interval"`
	GCEvery   Dur    `json:"gc_interval"`

	KeepBeacons  int `json:"keep_beacons_per_check"`
	BeaconMaxAge Dur `json:"beacon_max_age"`
	AlertMaxAge  Dur `json:"alert_max_age"`

	RatePerSec   float64 `json:"beat_rate_per_sec_per_client"`
	RateBurst    int     `json:"beat_burst"`
	MaxBodyBytes int64   `json:"max_body_bytes"`

	NotifyCmd string `json:"notify_cmd"`
	LogFormat string `json:"log_format"`
	LogLevel  string `json:"log_level"`

	// BeaconMode decides what a bare `knell beat <slug>` does: "record" writes
	// into the local database, "push" delivers to base_url. A single-node
	// install wants record; a fleet of cron boxes wants push.
	BeaconMode string `json:"beacon_mode"`

	// AdminToken is never read from the config file: it comes from
	// KNELL_ADMIN_TOKEN only, so a committed or backed-up config cannot carry
	// the credential that mints and deletes checks.
	AdminToken string `json:"-"`

	// AllowUnsigned is gone, and the reason is worth keeping in the file so it
	// does not come back: "did this arrive from loopback?" is not a capability
	// check. A TLS sidecar on the same host turns every internet client into a
	// loopback peer, so any mode that trusts peer position is defeated by the
	// deployment this project's own docs recommend. Beacons are signed, or the
	// check-in is written to the local database by the CLI.
}

// Dur is a time.Duration that reads as "15m" in JSON.
type Dur struct{ time.Duration }

func (d *Dur) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", s)
	}
	d.Duration = v
	return nil
}

func (d Dur) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func Default() Config {
	home, _ := os.UserHomeDir()
	data := filepath.Join(envOr("XDG_DATA_HOME", filepath.Join(home, ".local", "share")), "knell")
	conf := envOr("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return Config{
		DBPath:       filepath.Join(data, "knell.db"),
		KeysPath:     filepath.Join(conf, "knell", "keys.json"),
		Listen:       "127.0.0.1:8482",
		BaseURL:      "http://127.0.0.1:8482",
		Skew:         Dur{15 * time.Minute},
		EvalEvery:    Dur{30 * time.Second},
		GCEvery:      Dur{6 * time.Hour},
		KeepBeacons:  200,
		BeaconMaxAge: Dur{30 * 24 * time.Hour},
		AlertMaxAge:  Dur{90 * 24 * time.Hour},
		RatePerSec:   5,
		RateBurst:    20,
		MaxBodyBytes: 4096,
		LogFormat:    "text",
		LogLevel:     "info",
		BeaconMode:   "record",
	}
}

// File is the config path: $KNELL_CONFIG, else $XDG_CONFIG_HOME/knell/config.json.
func File() string {
	if p := os.Getenv("KNELL_CONFIG"); p != "" {
		return p
	}
	d := Default()
	return filepath.Join(filepath.Dir(d.KeysPath), "config.json")
}

// Load returns defaults merged with the file at path when it exists, then with
// environment overrides. A malformed file is an error: silently falling back to
// defaults would start a server on the wrong address.
func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		path = File()
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return c, fmt.Errorf("knell: reading %s: %w", path, err)
	default:
		if err := json.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("knell: parsing %s: %w", path, err)
		}
	}
	c.AdminToken = os.Getenv("KNELL_ADMIN_TOKEN")
	c.applyEnv()
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func (c *Config) applyEnv() {
	set := []struct {
		key string
		dst *string
	}{
		{"KNELL_DB", &c.DBPath},
		{"KNELL_KEYS", &c.KeysPath},
		{"KNELL_LISTEN", &c.Listen},
		{"KNELL_URL", &c.BaseURL},
		{"KNELL_NOTIFY_CMD", &c.NotifyCmd},
		{"KNELL_LOG_FORMAT", &c.LogFormat},
		{"KNELL_LOG_LEVEL", &c.LogLevel},
		{"KNELL_BEACON_MODE", &c.BeaconMode},
	}
	for _, s := range set {
		if v := os.Getenv(s.key); v != "" {
			*s.dst = v
		}
	}
	if v := os.Getenv("KNELL_SKEW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Skew = Dur{d}
		}
	}
	if v := os.Getenv("KNELL_KEEP_BEACONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.KeepBeacons = n
		}
	}
}

func (c *Config) Validate() error {
	if c.DBPath == "" {
		return errors.New("knell: db_path must not be empty")
	}
	if c.Listen == "" {
		return errors.New("knell: listen must not be empty")
	}
	if c.Skew.Duration <= 0 {
		c.Skew = Dur{15 * time.Minute}
	}
	if c.Skew.Duration > 0 && c.Skew.Duration > 24*time.Hour {
		return fmt.Errorf("knell: skew longer than 24h (%s) makes a captured beacon reusable for a day", c.Skew)
	}
	if c.EvalEvery.Duration <= 0 {
		c.EvalEvery = Dur{30 * time.Second}
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 4096
	}
	if c.KeepBeacons <= 0 {
		c.KeepBeacons = 200
	}
	switch c.LogFormat {
	case "text", "json", "":
	default:
		return fmt.Errorf("knell: log_format must be text or json, got %q", c.LogFormat)
	}
	if c.BeaconMode == "" {
		c.BeaconMode = "record"
	}
	switch c.BeaconMode {
	case "record", "push":
	default:
		return fmt.Errorf("knell: beacon_mode must be record or push, got %q", c.BeaconMode)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
