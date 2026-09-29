package controlv4

import "net/http"

// Only an accepted body shape can invoke the native read-deadline callback.
// Malformed or body-free routes still use the bounded write/publication path
// and reach their normal validation without requiring a read-capable host.
func operationsReadsBody(r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		len(r.TransferEncoding) != 0 || r.Body == nil || r.Body == http.NoBody || r.Header.Get("Content-Type") != "application/octet-stream" {
		return false
	}
	switch r.URL.Path {
	case "/operations/diagnostics", "/operations/diagnostics/incidents":
		return r.Method == http.MethodDelete && r.ContentLength == 16
	case "/operations/diagnostics/incidents/links":
		return r.Method == http.MethodPut && r.ContentLength == 32
	case "/operations/diagnostics/incidents/lookup":
		return r.Method == http.MethodPost && r.ContentLength == 16
	default:
		return false
	}
}
