// Package build carries version metadata, stamped at link time by the Makefile.
package build

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Set with -ldflags "-X github.com/0xCyrildev/knell/internal/build.Version=v1.0.0".
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

var once sync.Once

// fill adopts revision info from the VCS stamping that `go build` embeds, so a
// checkout built without ldflags still reports which commit it came from.
func fill() {
	once.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		if Commit == "" || Date == "" {
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if Commit == "" {
						Commit = s.Value
					}
				case "vcs.time":
					if Date == "" {
						Date = s.Value
					}
				}
			}
		}
		if Commit != "" && len(Commit) > 12 {
			Commit = Commit[:12]
		}
	})
}

// String is the one-line identity printed by `knell version` and /healthz.
func String() string {
	fill()
	var b strings.Builder
	fmt.Fprintf(&b, "%s", Version)
	if Commit != "" {
		fmt.Fprintf(&b, " (%s)", Commit)
	}
	if Date != "" {
		fmt.Fprintf(&b, " built %s", Date)
	}
	fmt.Fprintf(&b, " %s/%s %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
	return b.String()
}

// Short is the version alone, for JSON responses.
func Short() string {
	fill()
	return Version
}
