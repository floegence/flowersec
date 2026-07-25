package webtransport

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	quic "github.com/quic-go/quic-go"
)

func TestConfigUsesRequiredH3TransportWithoutApplicationEarlyData(t *testing.T) {
	config, err := newQUICConfig(DefaultLimits())
	if err != nil {
		t.Fatalf("newQUICConfig: %v", err)
	}
	if config.Allow0RTT {
		t.Fatal("WebTransport application 0-RTT must be disabled")
	}
	if !config.EnableDatagrams || !config.EnableStreamResetPartialDelivery {
		t.Fatal("WebTransport dependency-required QUIC capabilities are missing")
	}
	if config.InitialPacketSize != rawquic.MinimumInitialPacketSize {
		t.Fatalf("initial packet size = %d, want %d for a 1280-byte IP path", config.InitialPacketSize, rawquic.MinimumInitialPacketSize)
	}
	if config.MaxIncomingStreams != 130 || config.MaxIncomingUniStreams != MaxH3IncomingUniStreams {
		t.Fatalf("stream limits = bidi %d uni %d", config.MaxIncomingStreams, config.MaxIncomingUniStreams)
	}
	if config.Tracer == nil {
		t.Fatal("WebTransport must expose HTTP/3 qlog when QLOGDIR is set")
	}
	t.Setenv("QLOGDIR", t.TempDir())
	if trace := config.Tracer(context.Background(), true, quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4})); trace != nil {
		t.Fatal("WebTransport exposed qlog outside a release evidence run")
	}
	t.Setenv("FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE", "1")
	trace := config.Tracer(context.Background(), true, quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4}))
	if trace == nil {
		t.Fatal("WebTransport did not expose qlog during a release evidence run")
	}
	if err := trace.AddProducer().Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerConfigReservesLongLivedConnectStream(t *testing.T) {
	limits, err := BindSessionLimits(DefaultLimits(), 128)
	if err != nil {
		t.Fatal(err)
	}
	config, err := newServerQUICConfig(limits)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxIncomingStreams != 131 {
		t.Fatalf("server QUIC inbound streams = %d, want N+2 carrier streams plus CONNECT", config.MaxIncomingStreams)
	}
}
