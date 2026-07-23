package observability

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/fserrors"
)

func TestDiagnosticEventResourceFieldsAreOptionalAndGeneric(t *testing.T) {
	resource := "session_receive_bytes"
	current := int64(1025)
	limit := int64(1024)
	event := DiagnosticEvent{
		V:          1,
		Namespace:  "connect",
		Path:       "direct",
		Stage:      DiagnosticStageYamux,
		CodeDomain: DiagnosticCodeDomainEvent,
		Code:       "resource_limit_reached",
		Result:     DiagnosticResultFail,
		Resource:   &resource,
		Current:    &current,
		Limit:      &limit,
	}
	b, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["resource"] != resource || got["current"] != float64(current) || got["limit"] != float64(limit) {
		t.Fatalf("unexpected resource diagnostic: %s", b)
	}
	for _, forbidden := range []string{"url", "query", "token", "stream_kind", "payload"} {
		if _, ok := got[forbidden]; ok {
			t.Fatalf("diagnostic includes forbidden field %q: %s", forbidden, b)
		}
	}
}

type recordingClientObserver struct {
	mu          sync.Mutex
	connects    []ConnectReason
	diagnostics []DiagnosticEvent
}

func (o *recordingClientObserver) OnConnect(path fserrors.Path, result ConnectResult, reason ConnectReason, elapsed time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.connects = append(o.connects, reason)
}

func (o *recordingClientObserver) OnAttach(result AttachResult, reason AttachReason) {}

func (o *recordingClientObserver) OnHandshake(path fserrors.Path, result HandshakeResult, code fserrors.Code, elapsed time.Duration) {
}

func (o *recordingClientObserver) OnDiagnosticEvent(event DiagnosticEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.diagnostics = append(o.diagnostics, event)
}

func TestNormalizeClientObserver_AttachesAttemptAndCorrelation(t *testing.T) {
	traceID := "trace-0001"
	sessionID := "session-0001"
	rec := &recordingClientObserver{}
	obs := NormalizeClientObserver(rec, ClientObserverContext{
		Path:       fserrors.PathDirect,
		AttemptSeq: 3,
		TraceID:    &traceID,
		SessionID:  &sessionID,
	})
	obs.OnHandshake(fserrors.PathDirect, HandshakeResultFail, fserrors.CodeTimeout, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.diagnostics) == 0 {
		t.Fatal("expected diagnostics")
	}
	last := rec.diagnostics[len(rec.diagnostics)-1]
	if last.AttemptSeq != 3 || last.TraceID == nil || *last.TraceID != traceID || last.SessionID == nil || *last.SessionID != sessionID {
		t.Fatalf("unexpected diagnostic event: %+v", last)
	}
}

func TestNormalizeClientObserver_EmitsOverflowEvent(t *testing.T) {
	rec := &recordingClientObserver{}
	obs := NormalizeClientObserver(rec, ClientObserverContext{
		Path:           fserrors.PathTunnel,
		MaxQueuedItems: 4,
	})
	for i := 0; i < 10; i++ {
		obs.OnConnect(fserrors.PathTunnel, ConnectResultOK, "", 0)
	}
	time.Sleep(20 * time.Millisecond)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	found := false
	for _, event := range rec.diagnostics {
		if event.Code == "diagnostics_overflow" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected diagnostics_overflow event, got %+v", rec.diagnostics)
	}
}

func TestNormalizeClientObserver_TerminalEventSurvivesQueueSaturation(t *testing.T) {
	release := make(chan struct{})
	rec := &blockingDiagnosticObserver{release: release}
	obs := NormalizeClientObserver(rec, ClientObserverContext{
		Path:           fserrors.PathTunnel,
		MaxQueuedItems: 4,
	})
	for i := 0; i < 8; i++ {
		obs.OnConnect(fserrors.PathTunnel, ConnectResultOK, "", 0)
	}
	obs.OnHandshake(fserrors.PathTunnel, HandshakeResultFail, fserrors.CodeTimeout, 10*time.Millisecond)
	close(release)
	time.Sleep(20 * time.Millisecond)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	found := false
	for _, event := range rec.diagnostics {
		if event.Stage == DiagnosticStageHandshake && event.Code == string(fserrors.CodeTimeout) && event.Result == DiagnosticResultFail {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected terminal handshake diagnostic, got %+v", rec.diagnostics)
	}
}

func TestNormalizeClientObserver_ElapsedMSUsesAttemptStart(t *testing.T) {
	rec := &recordingClientObserver{}
	obs := NormalizeClientObserver(rec, ClientObserverContext{
		Path:         fserrors.PathDirect,
		AttemptStart: time.Now().Add(-250 * time.Millisecond),
	})
	obs.OnHandshake(fserrors.PathDirect, HandshakeResultOK, "", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.diagnostics) == 0 {
		t.Fatal("expected diagnostics")
	}
	last := rec.diagnostics[len(rec.diagnostics)-1]
	if last.ElapsedMS < 200 {
		t.Fatalf("expected elapsed_ms from attempt start, got %+v", last)
	}
}

type blockingDiagnosticObserver struct {
	mu          sync.Mutex
	diagnostics []DiagnosticEvent
	release     <-chan struct{}
}

func (o *blockingDiagnosticObserver) OnConnect(fserrors.Path, ConnectResult, ConnectReason, time.Duration) {
}
func (o *blockingDiagnosticObserver) OnAttach(AttachResult, AttachReason) {}
func (o *blockingDiagnosticObserver) OnHandshake(fserrors.Path, HandshakeResult, fserrors.Code, time.Duration) {
}
func (o *blockingDiagnosticObserver) OnDiagnosticEvent(event DiagnosticEvent) {
	<-o.release
	o.mu.Lock()
	defer o.mu.Unlock()
	o.diagnostics = append(o.diagnostics, event)
}
