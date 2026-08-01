package connectv2

import (
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
)

func TestBindQUICTimeoutsUsesArtifactSessionContract(t *testing.T) {
	limits := rawquic.DefaultLimits()
	limits.HandshakeIdleTimeout = 5 * time.Second
	limits.MaxIdleTimeout = 10 * time.Second
	limits.KeepAlivePeriod = 9 * time.Second
	contract := artifactv2.SessionContract{
		EstablishTimeoutSeconds: 30,
		IdleTimeoutSeconds:      60,
	}

	bindQUICTimeouts(&limits, contract)

	if got, want := limits.HandshakeIdleTimeout, 30*time.Second; got != want {
		t.Fatalf("handshake idle timeout = %s, want %s", got, want)
	}
	if got, want := limits.MaxIdleTimeout, 60*time.Second; got != want {
		t.Fatalf("session idle timeout = %s, want %s", got, want)
	}
	if got, want := limits.KeepAlivePeriod, 9*time.Second; got != want {
		t.Fatalf("keepalive period = %s, want %s", got, want)
	}
}
