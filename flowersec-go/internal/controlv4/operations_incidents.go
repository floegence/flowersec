package controlv4

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const (
	operationsIncidentSlots = 64
	operationsIncidentLinks = 32
	operationsIncidentMS    = 15 * 60 * 1000
)

type operationsIncidentLink struct {
	id      [16]byte
	expires time.Time
}

// Parent IDs and their associations exist only in this explicitly enabled
// management service. A row belongs to one immutable reader registration and
// one configured exporter scope, never a peer-supplied tenant or endpoint.
type operationsIncident struct {
	id       [16]byte
	reader   int
	deadline *timev4.Deadline
	links    [operationsIncidentLinks]operationsIncidentLink
}

func operationsIncidentCharge() resourcev4.Vector {
	return resourcev4.Vector{
		resourcev4.SDKBytes: operationsIncidentSlots * uint64(unsafe.Sizeof(operationsIncident{})+unsafe.Sizeof(timev4.Deadline{})),
		resourcev4.Items:    operationsIncidentSlots * (operationsIncidentLinks + 1), resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1,
	}
}

func (p *OperationsService) incidentAllowedLocked(reader int, now timev4.Sample) bool {
	return p.config.DiagnosticIncidents && p.config.Diagnostics != nil && p.currentLocked(reader, now) &&
		p.readers[reader].readDiagnostics && p.readers[reader].correlateDiagnostics
}

func (p *OperationsService) clearReaderIncidentsLocked(reader int) {
	for i := range p.incidents {
		if p.incidents[i].reader == reader {
			p.incidents[i] = operationsIncident{}
		}
	}
}

func (p *OperationsService) removeIncidentCorrelationLocked(id [16]byte, all bool) {
	for i := range p.incidents {
		for j := range p.incidents[i].links {
			if all || p.incidents[i].links[j].id == id {
				p.incidents[i].links[j] = operationsIncidentLink{}
			}
		}
	}
}

// incidentTime converts a trusted Unix-millisecond cap to the native wall
// clock representation used by net/http. The cap is created by timev4 and is
// never reconstructed from host wall time; rejecting an unrepresentable value
// keeps response publication fail-closed instead of wrapping int64.
func incidentTime(milliseconds uint64) (time.Time, bool) {
	if milliseconds > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(milliseconds)), true
}

// One admitted worker owns one timer for the entire finite table. Reads also
// sweep before publication, so scheduling delay never authorizes expired data.
// Time uncertainty is fail-closed for retention; it cannot renew an incident.
func (p *OperationsService) sweepIncidentsLocked(now timev4.Sample) time.Duration {
	if !now.BelongsTo(p.config.Clock) || now.UpperMS > math.MaxInt64 {
		clear(p.incidents)
		return time.Second
	}
	trustedMS := now.UpperMS
	delay := time.Second
	for i := range p.incidents {
		row := &p.incidents[i]
		if row.id == ([16]byte{}) {
			continue
		}
		if !p.incidentAllowedLocked(row.reader, now) {
			*row = operationsIncident{}
			continue
		}
		remaining, err := row.deadline.RemainingMSAt(now)
		if err != nil || remaining == 0 || remaining > operationsIncidentMS {
			*row = operationsIncident{}
			continue
		}
		delay = min(delay, time.Duration(remaining)*time.Millisecond)
		for j := range row.links {
			link := &row.links[j]
			if link.id == ([16]byte{}) {
				continue
			}
			if link.expires.IsZero() {
				*link = operationsIncidentLink{}
				continue
			}
			linkMS := link.expires.UnixMilli()
			if linkMS < 0 || uint64(linkMS) <= trustedMS || uint64(linkMS)-trustedMS > operationsIncidentMS {
				*link = operationsIncidentLink{}
			} else {
				delay = min(delay, time.Duration(uint64(linkMS)-trustedMS)*time.Millisecond)
			}
		}
	}
	return max(time.Millisecond, delay)
}

func (p *OperationsService) runIncidents() {
	timer := time.NewTimer(0)
	returned := false
	defer func() {
		failed := recover() != nil || !returned
		// Retire native timer backing before publishing worker completion or
		// refunding the original service reservation.
		timer.Stop()
		p.mu.Lock()
		if failed {
			if !p.closed {
				p.closed = true
				close(p.incidentStop)
			}
			clear(p.incidents)
			if p.cancel != nil {
				p.cancel()
			}
		}
		p.incidentRunning = false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	for {
		now, sampleErr := p.sample()
		p.mu.Lock()
		if p.closed || p.reservation.Check() != nil || p.dependencies.Check() != nil {
			clear(p.incidents)
			p.mu.Unlock()
			returned = true
			return
		}
		if sampleErr != nil {
			now = timev4.Sample{}
		}
		delay := p.sweepIncidentsLocked(now)
		wake, stop := p.incidentWake, p.incidentStop
		p.mu.Unlock()
		timer.Reset(delay)
		select {
		case <-timer.C:
		case <-wake:
		case <-stop:
		}
	}
}

func (p *OperationsService) wakeIncidentsLocked() {
	select {
	case p.incidentWake <- struct{}{}:
	default:
	}
}

// Body-carried identifiers avoid access-log URL retention. No route accepts a
// tenant selector, free-form incident name, stable object identifier or label.
func (p *OperationsService) serveIncident(ctx context.Context, reader int, w http.ResponseWriter, r *http.Request) {
	now, sampleErr := p.sample()
	p.mu.Lock()
	allowed := sampleErr == nil && p.incidentAllowedLocked(reader, now)
	p.mu.Unlock()
	if !allowed {
		http.Error(w, "incident access unavailable", http.StatusForbidden)
		return
	}
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.TransferEncoding) != 0 {
		http.Error(w, "invalid incident request", http.StatusBadRequest)
		return
	}
	create := r.URL.Path == "/operations/diagnostics/incidents" && r.Method == http.MethodPost
	remove := r.URL.Path == "/operations/diagnostics/incidents" && r.Method == http.MethodDelete
	link := r.URL.Path == "/operations/diagnostics/incidents/links" && r.Method == http.MethodPut
	lookup := r.URL.Path == "/operations/diagnostics/incidents/lookup" && r.Method == http.MethodPost
	if !create && !remove && !link && !lookup {
		http.Error(w, "invalid incident method", http.StatusMethodNotAllowed)
		return
	}
	var input [32]byte
	defer clear(input[:])
	if create {
		if r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody {
			http.Error(w, "invalid incident request", http.StatusBadRequest)
			return
		}
		// Randomness is outside every SDK gate, while the original bounded
		// HTTP work position remains occupied. No replacement worker is made.
		if _, err := rand.Read(input[:16]); err != nil || [16]byte(input[:16]) == ([16]byte{}) {
			http.Error(w, "incident unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		length := 16
		if link {
			length = 32
		}
		if r.ContentLength != int64(length) || r.Body == nil || r.Header.Get("Content-Type") != "application/octet-stream" {
			http.Error(w, "invalid incident request", http.StatusBadRequest)
			return
		}
		if _, err := io.ReadFull(r.Body, input[:length]); err != nil || [16]byte(input[:16]) == ([16]byte{}) || link && [16]byte(input[16:]) == ([16]byte{}) {
			http.Error(w, "invalid incident request", http.StatusBadRequest)
			return
		}
	}
	parent, correlation := [16]byte(input[:16]), [16]byte(input[16:])
	var ids [operationsIncidentLinks][16]byte
	defer clear(ids[:])
	count, capMS, expires, status := p.incidentAction(ctx, reader, parent, correlation, create, remove, link, ids[:])
	if status != http.StatusOK {
		http.Error(w, "incident unavailable", status)
		return
	}
	if remove || link {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var encodedIDs [operationsIncidentLinks]string
	defer clear(encodedIDs[:])
	for i := range count {
		encodedIDs[i] = hex.EncodeToString(ids[i][:])
	}
	body, err := json.Marshal(struct {
		ParentEventID string   `json:"parent_event_id"`
		ExpiresAtMS   uint64   `json:"expires_at_ms"`
		Correlations  []string `json:"correlation_ids"`
	}{hex.EncodeToString(parent[:]), capMS, encodedIDs[:count]})
	if err != nil || len(body) > OperationsResponseBytes {
		clear(body)
		http.Error(w, "incident unavailable", http.StatusServiceUnavailable)
		return
	}
	defer clear(body)
	deadline, _ := ctx.Deadline()
	if expires.Before(deadline) {
		deadline = expires
	}
	if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
		http.Error(w, "incident deadline unavailable", http.StatusServiceUnavailable)
		return
	}
	// The original request pins the clock while sampling outside the gate.
	now, sampleErr = p.sample()
	trustedNow, representable := incidentTime(now.UpperMS)
	allowed = sampleErr == nil && representable && trustedNow.Before(deadline) && p.incidentPublicationCurrent(ctx, reader, parent, ids[:count])
	if !allowed {
		http.Error(w, "incident access expired", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Validate the same original row after encoding and the native deadline call.
// Neither a new permission registration nor a new exporter value may replace
// the authority captured for this publication. The original expiry is never
// renewed by lookup. This gate contains no HTTP I/O or application callbacks.
func (p *OperationsService) incidentPublicationCurrent(ctx context.Context, reader int, parent [16]byte, ids [][16]byte) bool {
	now, err := p.sample()
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || !p.incidentAllowedLocked(reader, now) {
		return false
	}
	p.sweepIncidentsLocked(now)
	for i := range p.incidents {
		row := &p.incidents[i]
		if row.id != parent || row.reader != reader {
			continue
		}
		for _, id := range ids {
			found := false
			for _, link := range row.links {
				found = found || link.id == id
			}
			if !found {
				return false
			}
			if _, err := p.config.Diagnostics.CorrelationDeadline(ctx, id); err != nil {
				p.removeIncidentCorrelationLocked(id, false)
				return false
			}
		}
		return ctx.Err() == nil
	}
	return false
}

func (p *OperationsService) incidentAction(ctx context.Context, reader int, parent, correlation [16]byte, create, remove, link bool, ids [][16]byte) (count int, capMS uint64, expires time.Time, status int) {
	now, err := p.sample()
	if err != nil {
		return 0, 0, time.Time{}, http.StatusForbidden
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || !p.incidentAllowedLocked(reader, now) {
		return 0, 0, time.Time{}, http.StatusForbidden
	}
	p.sweepIncidentsLocked(now)
	index := -1
	for i, row := range p.incidents {
		if row.id == parent {
			if create || row.reader != reader {
				return 0, 0, time.Time{}, http.StatusNotFound
			}
			index = i
			break
		}
	}
	if create {
		for i, row := range p.incidents {
			if row.id == ([16]byte{}) {
				index = i
				break
			}
		}
		if index < 0 {
			return 0, 0, time.Time{}, http.StatusTooManyRequests
		}
		deadline, err := timev4.NewAgeAt(p.config.Clock, now, operationsIncidentMS, p.readers[reader].notAfter)
		if err != nil {
			return 0, 0, time.Time{}, http.StatusServiceUnavailable
		}
		remaining, err := deadline.RemainingMSAt(now)
		if err != nil || remaining == 0 {
			return 0, 0, time.Time{}, http.StatusServiceUnavailable
		}
		// The immutable absolute cap is the only retention authority. Do not
		// derive a second expiry from host wall time or from the timer's current
		// remaining projection: a delayed worker must never renew the incident.
		p.incidents[index] = operationsIncident{id: parent, reader: reader, deadline: deadline}
		p.wakeIncidentsLocked()
	}
	if index < 0 {
		return 0, 0, time.Time{}, http.StatusNotFound
	}
	row := &p.incidents[index]
	if remove {
		*row = operationsIncident{}
		return 0, 0, time.Time{}, http.StatusOK
	}
	if link {
		until, err := p.config.Diagnostics.CorrelationDeadline(ctx, correlation)
		if err != nil {
			return 0, 0, time.Time{}, http.StatusNotFound
		}
		free := -1
		for i, existing := range row.links {
			if existing.id == correlation {
				return 0, 0, time.Time{}, http.StatusOK
			}
			if existing.id == ([16]byte{}) && free < 0 {
				free = i
			}
		}
		if free < 0 {
			return 0, 0, time.Time{}, http.StatusTooManyRequests
		}
		row.links[free] = operationsIncidentLink{id: correlation, expires: until}
		p.wakeIncidentsLocked()
		return 0, 0, time.Time{}, http.StatusOK
	}
	capMS = row.deadline.Cap()
	var ok bool
	if expires, ok = incidentTime(capMS); !ok {
		return 0, 0, time.Time{}, http.StatusServiceUnavailable
	}
	for i := range row.links {
		entry := &row.links[i]
		if entry.id == ([16]byte{}) {
			continue
		}
		// A separately deleted exporter value cannot be recovered via an
		// incident. Revalidation never replaces its earlier captured expiry.
		if _, err := p.config.Diagnostics.CorrelationDeadline(ctx, entry.id); err != nil {
			*entry = operationsIncidentLink{}
			continue
		}
		ids[count] = entry.id
		count++
		if entry.expires.Before(expires) {
			expires = entry.expires
		}
	}
	return count, capMS, expires, http.StatusOK
}
