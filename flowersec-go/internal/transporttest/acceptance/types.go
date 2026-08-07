package acceptance

import (
	"errors"
	"path/filepath"
)

const (
	BrowserChromium       = "chromium"
	BrowserFirefox        = "firefox"
	BrowserDirectTopology = "browser_webtransport"
	BrowserTunnelWTWSS    = "browser_tunnel_wt_wss"
	BrowserTunnelWTQUIC   = "browser_tunnel_wt_quic"
	browserDirectTopology = BrowserDirectTopology
)

// RunContext identifies one runner-owned invocation. The test owns everything
// it creates beneath TempDir and every privileged resource derived from RunID.
type RunContext struct {
	RunID   string
	TempDir string
	Root    string
	Debug   bool
	Browser string
}

func (run RunContext) validate() error {
	if run.RunID == "" || !filepath.IsAbs(run.TempDir) || !filepath.IsAbs(run.Root) {
		return errors.New("acceptance run context is invalid")
	}
	if run.Browser != "" && run.Browser != BrowserChromium && run.Browser != BrowserFirefox {
		return errors.New("acceptance browser is invalid")
	}
	return nil
}

func (run RunContext) browser() string {
	if run.Browser == "" {
		return BrowserChromium
	}
	return run.Browser
}
