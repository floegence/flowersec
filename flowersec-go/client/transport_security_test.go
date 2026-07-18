package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/observability"
)

func TestTransportSecurityPresets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		policy  TransportSecurityPolicy
		rawURL  string
		allowed bool
	}{
		{name: "tls", policy: RequireTLS, rawURL: "wss://example.com/ws", allowed: true},
		{name: "tls rejects plaintext", policy: RequireTLS, rawURL: "ws://127.0.0.1/ws"},
		{name: "localhost", policy: AllowPlaintextForLoopback, rawURL: "ws://localhost/ws", allowed: true},
		{name: "ipv4 loopback range", policy: AllowPlaintextForLoopback, rawURL: "ws://127.42.0.9/ws", allowed: true},
		{name: "ipv6 loopback", policy: AllowPlaintextForLoopback, rawURL: "ws://[::1]/ws", allowed: true},
		{name: "dns name is not resolved", policy: AllowPlaintextForLoopback, rawURL: "ws://loopback.example/ws"},
		{name: "fake localhost", policy: AllowPlaintextForLoopback, rawURL: "ws://localhost.example/ws"},
		{name: "short ipv4", policy: AllowPlaintextForLoopback, rawURL: "ws://127.1/ws"},
		{name: "leading zero ipv4", policy: AllowPlaintextForLoopback, rawURL: "ws://127.0.00.1/ws"},
		{name: "integer ipv4", policy: AllowPlaintextForLoopback, rawURL: "ws://2130706433/ws"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := evaluateTransportSecurity(context.Background(), tt.rawURL, fserrors.PathDirect, tt.policy, observability.NoopClientObserver)
			if tt.allowed && err != nil {
				t.Fatalf("evaluateTransportSecurity() error = %v", err)
			}
			if !tt.allowed {
				var structured *fserrors.Error
				if !errors.As(err, &structured) || structured.Code != fserrors.CodeTransportPolicyDenied {
					t.Fatalf("error = %v, want transport policy denial", err)
				}
			}
		})
	}
}

func TestTransportSecurityCustomPolicyReceivesSanitizedInput(t *testing.T) {
	t.Parallel()
	called := false
	policy := func(_ context.Context, input TransportSecurityPolicyInput) error {
		called = true
		if input.Path != fserrors.PathTunnel || input.Scheme != "wss" || input.Host != "example.com" || input.Runtime != TransportRuntimeNative {
			t.Fatalf("unexpected input: %+v", input)
		}
		return nil
	}
	err := evaluateTransportSecurity(context.Background(), "wss://example.com/private?token=secret", fserrors.PathTunnel, policy, observability.NoopClientObserver)
	if err != nil || !called {
		t.Fatalf("evaluateTransportSecurity() = %v, called = %v", err, called)
	}
}

func TestTransportSecurityCustomPolicyCannotAllowNonWebSocketScheme(t *testing.T) {
	t.Parallel()
	called := false
	policy := func(context.Context, TransportSecurityPolicyInput) error {
		called = true
		return nil
	}
	err := evaluateTransportSecurity(context.Background(), "https://example.com/ws", fserrors.PathDirect, policy, observability.NoopClientObserver)
	var structured *fserrors.Error
	if !errors.As(err, &structured) || structured.Code != fserrors.CodeTransportPolicyDenied {
		t.Fatalf("error = %v, want transport policy denial", err)
	}
	if called {
		t.Fatal("custom policy was called for a non-WebSocket scheme")
	}
}

func TestTransportSecurityLoopbackPlaintextPolicyEmitsDiagnostic(t *testing.T) {
	t.Parallel()
	recorder := &transportDiagnosticObserver{events: make(chan observability.DiagnosticEvent, 2)}
	observer := observability.NormalizeClientObserver(recorder, observability.ClientObserverContext{Path: fserrors.PathDirect})
	err := evaluateTransportSecurity(context.Background(), "ws://localhost/ws", fserrors.PathDirect, AllowPlaintextForLoopback, observer)
	if err != nil {
		t.Fatalf("evaluateTransportSecurity() error = %v", err)
	}
	select {
	case event := <-recorder.events:
		if event.Code != "plaintext_transport" || event.Path != string(fserrors.PathDirect) || event.Stage != observability.DiagnosticStageTransport {
			t.Fatalf("unexpected diagnostic: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("missing plaintext diagnostic")
	}
	select {
	case duplicate := <-recorder.events:
		t.Fatalf("duplicate plaintext diagnostic: %+v", duplicate)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTransportSecurityMissingPolicyDoesNotEmitPlaintextDiagnostic(t *testing.T) {
	t.Parallel()
	recorder := &transportDiagnosticObserver{events: make(chan observability.DiagnosticEvent, 1)}
	observer := observability.NormalizeClientObserver(recorder, observability.ClientObserverContext{Path: fserrors.PathDirect})
	if err := evaluateTransportSecurity(context.Background(), "ws://example.com/ws", fserrors.PathDirect, nil, observer); err == nil {
		t.Fatal("evaluateTransportSecurity() error = nil, want TLS policy denial")
	}
	select {
	case event := <-recorder.events:
		t.Fatalf("unexpected plaintext diagnostic: %+v", event)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestNetworkPlaintextPolicy(t *testing.T) {
	policy, err := NewNetworkPlaintextPolicy(NetworkPlaintextPolicyOptions{
		AllowedHosts:   []string{"192.168.1.20", "2001:db8::20"},
		RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure,
	})
	if err != nil {
		t.Fatalf("NewNetworkPlaintextPolicy() error = %v", err)
	}
	for _, tc := range []struct {
		url     string
		allowed bool
	}{
		{url: "wss://service.example/ws", allowed: true},
		{url: "ws://192.168.1.20/ws", allowed: true},
		{url: "ws://[2001:db8::20]/ws", allowed: true},
		{url: "ws://192.168.1.21/ws", allowed: false},
		{url: "ws://127.0.0.1/ws", allowed: false},
	} {
		err := evaluateTransportSecurity(context.Background(), tc.url, fserrors.PathDirect, policy, observability.NoopClientObserver)
		if tc.allowed && err != nil {
			t.Fatalf("evaluateTransportSecurity(%q) error = %v", tc.url, err)
		}
		if !tc.allowed && err == nil {
			t.Fatalf("evaluateTransportSecurity(%q) error = nil", tc.url)
		}
	}
}

func TestNetworkPlaintextPolicyRejectsUnsafeOptions(t *testing.T) {
	for _, tc := range []NetworkPlaintextPolicyOptions{
		{AllowedHosts: []string{"192.168.1.20"}},
		{RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"localhost"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"127.0.0.1"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"0.0.0.0"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"example.com"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"192.168.001.20"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"[2001:db8::20]"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"fe80::1"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
		{AllowedHosts: []string{"::ffff:192.168.1.20"}, RiskAcceptance: PlaintextRiskAcceptPreE2ECredentialExposure},
	} {
		if _, err := NewNetworkPlaintextPolicy(tc); err == nil {
			t.Fatalf("NewNetworkPlaintextPolicy(%#v) error = nil", tc)
		}
	}
}

type transportDiagnosticObserver struct {
	events chan observability.DiagnosticEvent
}

func (*transportDiagnosticObserver) OnConnect(fserrors.Path, observability.ConnectResult, observability.ConnectReason, time.Duration) {
}
func (*transportDiagnosticObserver) OnAttach(observability.AttachResult, observability.AttachReason) {
}
func (*transportDiagnosticObserver) OnHandshake(fserrors.Path, observability.HandshakeResult, fserrors.Code, time.Duration) {
}
func (o *transportDiagnosticObserver) OnDiagnosticEvent(event observability.DiagnosticEvent) {
	o.events <- event
}
