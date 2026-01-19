package ws

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// IsOriginAllowed validates r.Header["Origin"] against an allow-list.
//
// Allowed entries support:
//   - Full Origin values with scheme, e.g. "https://example.com" or "http://127.0.0.1:5173"
//   - Hostnames, e.g. "example.com"
//   - Wildcard hostnames, e.g. "*.example.com" (matches both example.com and subdomains)
//   - Exact non-standard Origin values, e.g. "null"
//
// If the request has no Origin header, allowNoOrigin controls acceptance.
func IsOriginAllowed(r *http.Request, allowed []string, allowNoOrigin bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return allowNoOrigin
	}
	parsed, err := url.Parse(origin)
	host := ""
	hostname := ""
	if err == nil {
		host = parsed.Host
		hostname = parsed.Hostname()
	}
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// If entry contains a scheme, treat it as a full Origin value match.
		if strings.Contains(entry, "://") {
			if origin == entry {
				return true
			}
			continue
		}
		// Support wildcard hostname entries like "*.example.com".
		// For usability, treat "*.example.com" as matching both "example.com"
		// and any subdomain (e.g. "a.example.com").
		if strings.HasPrefix(entry, "*.") {
			base := strings.TrimPrefix(entry, "*.")
			if hostname != "" && base != "" {
				if hostname == base || strings.HasSuffix(hostname, "."+base) {
					return true
				}
			}
			continue
		}
		// If the entry looks like host:port, compare it against the parsed Host.
		// This keeps the "example.com" form as hostname-only, while enabling an explicit port allow-list.
		if host != "" {
			if _, _, err := net.SplitHostPort(entry); err == nil {
				if host == entry {
					return true
				}
				continue
			}
		}
		// Otherwise, treat it as a hostname allow-list entry (e.g. "example.com").
		if hostname != "" && hostname == entry {
			return true
		}
		// Also allow exact string matches for non-standard Origin values (e.g. "null").
		if origin == entry {
			return true
		}
	}
	return false
}

// NewOriginChecker returns a websocket upgrader CheckOrigin function.
func NewOriginChecker(allowed []string, allowNoOrigin bool) func(r *http.Request) bool {
	return func(r *http.Request) bool {
		return IsOriginAllowed(r, allowed, allowNoOrigin)
	}
}
