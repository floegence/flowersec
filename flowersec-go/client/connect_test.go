package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

const testConnectPSK = "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg"

type connectArtifactRecordingObserver struct {
	mu          sync.Mutex
	diagnostics []observability.DiagnosticEvent
}

func (o *connectArtifactRecordingObserver) OnConnect(fserrors.Path, observability.ConnectResult, observability.ConnectReason, time.Duration) {
}

func (o *connectArtifactRecordingObserver) OnAttach(observability.AttachResult, observability.AttachReason) {
}

func (o *connectArtifactRecordingObserver) OnHandshake(fserrors.Path, observability.HandshakeResult, fserrors.Code, time.Duration) {
}

func (o *connectArtifactRecordingObserver) OnDiagnosticEvent(event observability.DiagnosticEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.diagnostics = append(o.diagnostics, event)
}

func (o *connectArtifactRecordingObserver) diagnostic(code string) (observability.DiagnosticEvent, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, event := range o.diagnostics {
		if event.Stage == observability.DiagnosticStageScope && event.Code == code && event.Result == observability.DiagnosticResultSkip {
			return event, true
		}
	}
	return observability.DiagnosticEvent{}, false
}

func waitConnectDiagnostic(t *testing.T, observer *connectArtifactRecordingObserver, code string) observability.DiagnosticEvent {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if event, ok := observer.diagnostic(code); ok {
			return event
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for diagnostic %q", code)
	return observability.DiagnosticEvent{}
}

func directConnectArtifact(scoped ...protocolio.ScopeMetadataEntry) *protocolio.ConnectArtifact {
	return &protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportDirect,
		DirectInfo: &directv1.DirectConnectInfo{
			WsUrl:                    "",
			ChannelId:                "chan_1",
			E2eePskB64u:              testConnectPSK,
			ChannelInitExpireAtUnixS: 123,
			DefaultSuite:             directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
		},
		Scoped: scoped,
	}
}

func TestConnectRejectsNilArtifact(t *testing.T) {
	_, err := Connect(context.Background(), nil, WithOrigin("http://example.com"))
	assertConnectError(t, err, PathAuto, StageValidate, CodeInvalidInput)
}

func TestConnectAcceptsDirectArtifact(t *testing.T) {
	_, err := Connect(context.Background(), directConnectArtifact(), WithOrigin("http://example.com"))
	assertConnectError(t, err, PathDirect, StageValidate, CodeMissingWSURL)
}

func TestConnectAcceptsTunnelArtifact(t *testing.T) {
	artifact := &protocolio.ConnectArtifact{
		V:         1,
		Transport: protocolio.ConnectArtifactTransportTunnel,
		TunnelGrant: &controlv1.ChannelInitGrant{
			TunnelUrl:                "",
			ChannelId:                "chan_1",
			ChannelInitExpireAtUnixS: 123,
			IdleTimeoutSeconds:       30,
			Role:                     controlv1.Role_client,
			Token:                    "tok",
			E2eePskB64u:              testConnectPSK,
			AllowedSuites:            []controlv1.Suite{controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM},
			DefaultSuite:             controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM,
		},
	}

	_, err := Connect(context.Background(), artifact, WithOrigin("http://example.com"))
	assertConnectError(t, err, PathTunnel, StageValidate, CodeMissingTunnelURL)
}

func TestConnectStrictArtifactValidationFailsFast(t *testing.T) {
	artifact := directConnectArtifact(
		protocolio.ScopeMetadataEntry{Scope: "proxy.runtime", ScopeVersion: 1, Critical: false, Payload: protocolio.ScopePayload{}},
		protocolio.ScopeMetadataEntry{Scope: "proxy.runtime", ScopeVersion: 1, Critical: false, Payload: protocolio.ScopePayload{}},
	)

	_, err := Connect(context.Background(), artifact, WithOrigin("http://example.com"))
	assertConnectError(t, err, PathDirect, StageValidate, CodeInvalidInput)
}

func TestConnectArtifactCriticalScopeWithoutResolverFailsFast(t *testing.T) {
	artifact := directConnectArtifact(protocolio.ScopeMetadataEntry{
		Scope: "proxy.runtime", ScopeVersion: 2, Critical: true, Payload: protocolio.ScopePayload{"mode": "strict"},
	})

	_, err := Connect(context.Background(), artifact, WithOrigin("http://example.com"))
	assertConnectError(t, err, PathDirect, StageValidate, CodeResolveFailed)
}

func TestConnectArtifactOptionalScopeWithoutResolverIsIgnored(t *testing.T) {
	recorder := &connectArtifactRecordingObserver{}
	traceID := "trace-artifact-1"
	sessionID := "session-artifact-1"
	artifact := directConnectArtifact(protocolio.ScopeMetadataEntry{
		Scope: "proxy.runtime", ScopeVersion: 2, Critical: false, Payload: protocolio.ScopePayload{"mode": "hint"},
	})
	artifact.Correlation = &protocolio.CorrelationContext{
		V:         1,
		TraceID:   &traceID,
		SessionID: &sessionID,
		Tags:      []protocolio.CorrelationKV{},
	}

	_, err := Connect(context.Background(), artifact, WithOrigin("http://example.com"), WithObserver(recorder))
	assertConnectError(t, err, PathDirect, StageValidate, CodeMissingWSURL)
	event := waitConnectDiagnostic(t, recorder, "scope_ignored_missing_resolver")
	if event.TraceID == nil || *event.TraceID != traceID || event.SessionID == nil || *event.SessionID != sessionID {
		t.Fatalf("expected artifact correlation on diagnostic, got trace_id=%v session_id=%v", event.TraceID, event.SessionID)
	}
}

func TestConnectArtifactScopeResolverReceivesScopeVersion(t *testing.T) {
	var got protocolio.ScopeMetadataEntry
	artifact := directConnectArtifact(protocolio.ScopeMetadataEntry{
		Scope: "proxy.runtime", ScopeVersion: 2, Critical: true, Payload: protocolio.ScopePayload{"mode": "strict"},
	})

	_, err := Connect(context.Background(), artifact,
		WithOrigin("http://example.com"),
		WithScopeResolver("proxy.runtime", func(_ context.Context, entry protocolio.ScopeMetadataEntry) error {
			got = entry
			return nil
		}),
	)
	if err == nil {
		t.Fatal("expected direct validation error")
	}
	if got.ScopeVersion != 2 || got.Scope != "proxy.runtime" {
		t.Fatalf("unexpected resolver entry: %#v", got)
	}
}

func TestConnectArtifactOptionalScopeResolverFailureFailsFastByDefault(t *testing.T) {
	artifact := directConnectArtifact(protocolio.ScopeMetadataEntry{
		Scope: "proxy.runtime", ScopeVersion: 2, Critical: false, Payload: protocolio.ScopePayload{"mode": "bad"},
	})

	_, err := Connect(context.Background(), artifact,
		WithOrigin("http://example.com"),
		WithScopeResolver("proxy.runtime", func(context.Context, protocolio.ScopeMetadataEntry) error {
			return errors.New("bad payload")
		}),
	)
	assertConnectError(t, err, PathDirect, StageValidate, CodeResolveFailed)
}

func TestConnectArtifactOptionalScopeResolverFailureCanBeRelaxed(t *testing.T) {
	recorder := &connectArtifactRecordingObserver{}
	artifact := directConnectArtifact(protocolio.ScopeMetadataEntry{
		Scope: "proxy.runtime", ScopeVersion: 2, Critical: false, Payload: protocolio.ScopePayload{"mode": "bad"},
	})

	_, err := Connect(context.Background(), artifact,
		WithOrigin("http://example.com"),
		WithScopeResolver("proxy.runtime", func(context.Context, protocolio.ScopeMetadataEntry) error {
			return errors.New("bad payload")
		}),
		WithRelaxedOptionalScopeValidation(true),
		WithObserver(recorder),
	)
	assertConnectError(t, err, PathDirect, StageValidate, CodeMissingWSURL)
	waitConnectDiagnostic(t, recorder, "scope_ignored_relaxed_validation")
}

func assertConnectError(t *testing.T, err error, path Path, stage Stage, code Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	var flowersecError *Error
	if !errors.As(err, &flowersecError) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if flowersecError.Path != path || flowersecError.Stage != stage || flowersecError.Code != code {
		t.Fatalf("unexpected error: %+v", flowersecError)
	}
}
