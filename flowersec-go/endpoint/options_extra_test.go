package endpoint

import (
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestConnectOptions_AdditionalStableOptions(t *testing.T) {
	dialer := &websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	cache := NewHandshakeCache()
	yamuxLimits := YamuxLimits{MaxActiveStreams: 8, MaxInboundStreams: 4}

	cfg, err := applyConnectOptions([]ConnectOption{
		WithOrigin("https://app.example.com"),
		WithDialer(dialer),
		WithConnectTimeout(5 * time.Second),
		WithHandshakeTimeout(7 * time.Second),
		WithMaxHandshakePayload(8 * 1024),
		WithMaxRecordBytes(1 << 20),
		WithMaxBufferedBytes(1 << 16),
		WithServerFeatures(7),
		WithClockSkew(2 * time.Second),
		WithEndpointInstanceID("endpoint-instance-1"),
		WithHandshakeCache(cache),
		WithYamuxLimits(yamuxLimits),
		WithLivenessDisabled(),
		WithOutboundRecordChunkBytes(32 * 1024),
		WithTransportSecurityPolicy(RequireTLS),
	})
	if err != nil {
		t.Fatalf("applyConnectOptions() failed: %v", err)
	}

	if cfg.origin != "https://app.example.com" {
		t.Fatalf("origin = %q", cfg.origin)
	}
	if cfg.dialer != dialer {
		t.Fatal("dialer mismatch")
	}
	if cfg.connectTimeout != 5*time.Second {
		t.Fatalf("connectTimeout = %v", cfg.connectTimeout)
	}
	if cfg.handshakeTimeout != 7*time.Second {
		t.Fatalf("handshakeTimeout = %v", cfg.handshakeTimeout)
	}
	if cfg.maxHandshakePayload != 8*1024 {
		t.Fatalf("maxHandshakePayload = %d", cfg.maxHandshakePayload)
	}
	if cfg.maxRecordBytes != 1<<20 {
		t.Fatalf("maxRecordBytes = %d", cfg.maxRecordBytes)
	}
	if cfg.maxBufferedBytes != 1<<16 {
		t.Fatalf("maxBufferedBytes = %d", cfg.maxBufferedBytes)
	}
	if cfg.serverFeatures != 7 {
		t.Fatalf("serverFeatures = %d", cfg.serverFeatures)
	}
	if cfg.clockSkew != 2*time.Second {
		t.Fatalf("clockSkew = %v", cfg.clockSkew)
	}
	if cfg.endpointInstanceID != "endpoint-instance-1" || !cfg.endpointInstanceIDSet {
		t.Fatalf("endpointInstanceID = %q set=%v", cfg.endpointInstanceID, cfg.endpointInstanceIDSet)
	}
	if cfg.handshakeCache != cache {
		t.Fatal("handshake cache mismatch")
	}
	if cfg.yamuxLimits.MaxActiveStreams != 8 || cfg.yamuxLimits.MaxInboundStreams != 4 {
		t.Fatal("yamux limits mismatch")
	}
	if !cfg.livenessDisabled || !cfg.livenessSet {
		t.Fatalf("livenessDisabled = %v set=%v", cfg.livenessDisabled, cfg.livenessSet)
	}
	if cfg.outboundRecordChunkBytes != 32*1024 {
		t.Fatalf("outboundRecordChunkBytes = %d", cfg.outboundRecordChunkBytes)
	}
	if cfg.transportSecurityPolicy == nil {
		t.Fatal("transport security policy missing")
	}
}

func TestConnectOptions_RejectInvalidStableValues(t *testing.T) {
	tests := []struct {
		name string
		opt  ConnectOption
	}{
		{name: "negative connect timeout", opt: WithConnectTimeout(-time.Second)},
		{name: "negative handshake timeout", opt: WithHandshakeTimeout(-time.Second)},
		{name: "zero max handshake payload", opt: WithMaxHandshakePayload(0)},
		{name: "zero max record bytes", opt: WithMaxRecordBytes(0)},
		{name: "zero max buffered bytes", opt: WithMaxBufferedBytes(0)},
		{name: "negative clock skew", opt: WithClockSkew(-time.Second)},
		{name: "zero liveness interval", opt: WithLiveness(LivenessOptions{Timeout: time.Second})},
		{name: "zero outbound chunk", opt: WithOutboundRecordChunkBytes(0)},
		{name: "nil transport policy", opt: WithTransportSecurityPolicy(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := applyConnectOptions([]ConnectOption{tt.opt}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestConnectOptions_DefaultToRequireTLS(t *testing.T) {
	cfg, err := applyConnectOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.transportSecurityPolicy == nil {
		t.Fatal("expected default transport security policy")
	}
	if err := cfg.transportSecurityPolicy(t.Context(), TransportSecurityPolicyInput{Scheme: "ws"}); err == nil {
		t.Fatal("expected default policy to reject plaintext")
	}
}
