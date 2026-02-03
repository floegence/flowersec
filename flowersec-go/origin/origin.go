package origin

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// FromWSURL converts a websocket URL (ws:// or wss://) to an HTTP Origin (http(s)://host[:port]).
//
// This is useful for Flowersec tunnel/direct clients that need an Origin policy derived from a websocket URL.
func FromWSURL(wsURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(wsURL))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", errors.New("ws url missing host")
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "wss":
		return "https://" + u.Host, nil
	case "ws":
		return "http://" + u.Host, nil
	default:
		return "", fmt.Errorf("unsupported ws scheme: %s", u.Scheme)
	}
}

// ForTunnel returns an Origin value for a tunnel connection.
//
// It prefers controlplaneBaseURL (http/https) to keep the Origin policy stable across official/custom tunnels.
// When controlplaneBaseURL is missing or invalid, it falls back to deriving the Origin from tunnelURL (ws/wss).
func ForTunnel(tunnelURL string, controlplaneBaseURL string) (string, error) {
	if strings.TrimSpace(controlplaneBaseURL) != "" {
		u, err := url.Parse(strings.TrimSpace(controlplaneBaseURL))
		if err == nil && strings.TrimSpace(u.Host) != "" {
			scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
			if scheme == "http" || scheme == "https" {
				return scheme + "://" + u.Host, nil
			}
		}
	}
	return FromWSURL(tunnelURL)
}
