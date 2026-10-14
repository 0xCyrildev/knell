package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cmdPing asks a collector whether it is alive. It exists so a container health
// check can be one line of the binary itself rather than a shell plus curl in a
// distroless image — and so the answer is an exit code, not a paragraph.
func (a *app) cmdPing(args []string) int {
	fs, jsonOut, quiet := a.newFlagSet("ping")
	url := fs.String("url", "", "health endpoint to probe (default: <base_url>/healthz)")
	timeout := fs.Duration("timeout", 5*time.Second, "budget for the request")
	fs.Usage = func() {
		fmt.Fprint(a.stderr, `usage: knell ping [--url URL] [--json] [--quiet]

Exit codes: 0 the collector answered, 1 it did not, 2 knell could not run the check.

  knell ping                 is my configured collector up?
  knell ping --url https://knell.example/healthz
`)
		fs.PrintDefaults()
	}
	if err := a.parse(fs, args); err != nil {
		return exitError
	}
	if err := a.applyStateFlags(fs); err != nil {
		return a.fail(err)
	}

	target := *url
	if target == "" {
		target = strings.TrimRight(a.cfg.BaseURL, "/") + "/healthz"
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return a.fail(err)
	}
	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("knell: %s redirected; a health endpoint should not", target)
		},
	}
	res, err := client.Do(req)
	if err != nil {
		if !*quiet {
			fmt.Fprintf(a.stderr, "knell: %v\n", err)
		}
		return 1
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))

	var doc struct {
		OK      bool   `json:"ok"`
		Time    string `json:"time"`
		Version string `json:"version"`
	}
	decoded := json.Unmarshal(body, &doc) == nil
	up := res.StatusCode == http.StatusOK && decoded && doc.OK

	if *jsonOut {
		fmt.Fprintf(a.stdout, "%s\n", mustJSON(map[string]any{
			"url": target, "up": up, "status": res.StatusCode,
			"version": doc.Version, "server_time": doc.Time,
		}))
	} else if !*quiet {
		if up {
			fmt.Fprintf(a.stdout, "%s is up (knell %s, server time %s)\n", target, doc.Version, doc.Time)
		} else {
			fmt.Fprintf(a.stdout, "%s is not healthy (HTTP %d)\n", target, res.StatusCode)
		}
	}
	if up {
		return exitOK
	}
	return 1
}
