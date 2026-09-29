package controlv4

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
)

// These routes share the management listener's original single work position,
// rate window, finite response storage and exact mTLS registration. Diagnostic
// read/deletion are separate explicit rights. Neither exposes protocol state
// mutation, arbitrary selectors or another tenant/exporter selection input.
func (p *OperationsService) serveDiagnostics(ctx context.Context, reader int, w http.ResponseWriter, r *http.Request) {
	now, sampleErr := p.sample()
	p.mu.Lock()
	current := sampleErr == nil && p.currentLocked(reader, now)
	exporter := p.config.Diagnostics
	var read, remove bool
	if current {
		read, remove = p.readers[reader].readDiagnostics, p.readers[reader].deleteDiagnostics
	}
	p.mu.Unlock()
	if !current || exporter == nil || r.Method == http.MethodGet && !read || r.Method == http.MethodDelete && !remove {
		http.Error(w, "diagnostic access unavailable", http.StatusForbidden)
		return
	}
	if r.URL.RawPath != "" || r.URL.ForceQuery || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid diagnostic request", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/operations/diagnostics" || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody {
			http.Error(w, "invalid diagnostic request", http.StatusBadRequest)
			return
		}
		offset, count, ok := diagnosticPage(r.URL.RawQuery)
		if !ok {
			http.Error(w, "invalid diagnostic page", http.StatusBadRequest)
			return
		}
		var events [64]diagnosticv4.Event
		defer clear(events[:])
		n, next, err := exporter.Copy(ctx, offset, events[:count])
		if err != nil {
			http.Error(w, "diagnostics unavailable", http.StatusServiceUnavailable)
			return
		}
		deadline, _ := ctx.Deadline()
		for _, event := range events[:n] {
			if expires := event.RetentionDeadline(); expires.Before(deadline) {
				deadline = expires
			}
		}
		body, err := json.Marshal(struct {
			Events []diagnosticv4.Event `json:"events"`
			Next   uint32               `json:"next"`
		}{Events: events[:n], Next: next})
		if err != nil || len(body) > OperationsResponseBytes {
			clear(body)
			http.Error(w, "diagnostics unavailable", http.StatusServiceUnavailable)
			return
		}
		defer clear(body)
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
			http.Error(w, "diagnostic deadline unavailable", http.StatusServiceUnavailable)
			return
		}
		// The host wall clock is only used as the native socket write hint above.
		// Authorization and retention are rechecked against the deployment's
		// qualified clock so a wall-clock jump cannot extend this response.
		if ctx.Err() != nil || !p.current(reader) || !p.diagnosticDeadlinesValid(ctx, events[:n]) {
			http.Error(w, "diagnostic access expired", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	case http.MethodDelete:
		if r.URL.RawQuery != "" {
			http.Error(w, "invalid diagnostic deletion", http.StatusBadRequest)
			return
		}
		var id [16]byte
		defer clear(id[:])
		all := r.URL.Path == "/operations/diagnostics/all"
		if all {
			if r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody {
				http.Error(w, "invalid diagnostic deletion", http.StatusBadRequest)
				return
			}
		} else {
			// A binary fixed-width body avoids putting correlation IDs in URL
			// access logs or admitting an extensible JSON command language.
			if r.ContentLength != int64(len(id)) || r.Body == nil || r.Header.Get("Content-Type") != "application/octet-stream" {
				http.Error(w, "invalid diagnostic deletion", http.StatusBadRequest)
				return
			}
			if _, err := io.ReadFull(r.Body, id[:]); err != nil || id == ([16]byte{}) {
				http.Error(w, "invalid diagnostic deletion", http.StatusBadRequest)
				return
			}
		}
		// Only fixed in-memory deletion runs under this authorization gate.
		// Revocation winning first prevents mutation; no external I/O, code or
		// callback is invoked while this gate is held.
		now, sampleErr = p.sample()
		p.mu.Lock()
		allowed := sampleErr == nil && ctx.Err() == nil && p.currentLocked(reader, now) && p.readers[reader].deleteDiagnostics
		var err error
		if allowed {
			if all {
				err = exporter.DeleteAll(ctx)
			} else {
				err = exporter.DeleteCorrelation(ctx, id)
			}
			if err == nil {
				p.removeIncidentCorrelationLocked(id, all)
			}
		}
		p.mu.Unlock()
		if !allowed {
			http.Error(w, "diagnostic access unavailable", http.StatusForbidden)
			return
		}
		if err != nil {
			http.Error(w, "diagnostics unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "invalid diagnostic method", http.StatusMethodNotAllowed)
	}
}

func (p *OperationsService) diagnosticDeadlinesValid(ctx context.Context, events []diagnosticv4.Event) bool {
	if p == nil || p.config.Clock == nil || ctx == nil {
		return false
	}
	sample, err := p.config.Clock.Sample()
	if err != nil {
		return false
	}
	if deadline, ok := ctx.Deadline(); ok {
		ms := deadline.UnixMilli()
		if ms < 0 || !sample.Interval.ValidBefore(uint64(ms)) {
			return false
		}
	}
	for _, event := range events {
		expires := event.RetentionDeadline()
		if expires.IsZero() {
			continue
		}
		ms := expires.UnixMilli()
		if ms < 0 || !sample.Interval.ValidBefore(uint64(ms)) {
			return false
		}
	}
	return true
}

func diagnosticPage(raw string) (offset uint32, count int, ok bool) {
	if len(raw) > 64 {
		return
	}
	query, err := url.ParseQuery(raw)
	if err != nil || len(query) > 2 {
		return
	}
	count = 64
	for key, values := range query {
		if len(values) != 1 || len(values[0]) == 0 {
			return 0, 0, false
		}
		n, err := strconv.ParseUint(values[0], 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != values[0] {
			return 0, 0, false
		}
		switch key {
		case "offset":
			if n > 4096 {
				return 0, 0, false
			}
			offset = uint32(n)
		case "limit":
			if n == 0 || n > 64 {
				return 0, 0, false
			}
			count = int(n)
		default:
			return 0, 0, false
		}
	}
	return offset, count, true
}
