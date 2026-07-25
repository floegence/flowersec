package rawquic

import (
	"context"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestConfigUsesNativeBoundedQUICCapabilities(t *testing.T) {
	limits := Limits{
		MaxInboundStreams:              17,
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         2 << 20,
		InitialConnectionReceiveWindow: 256 << 10,
		MaxConnectionReceiveWindow:     8 << 20,
		HandshakeIdleTimeout:           7 * time.Second,
		MaxIdleTimeout:                 45 * time.Second,
		KeepAlivePeriod:                12 * time.Second,
	}
	config, err := newConfig(limits)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if config.MaxIncomingStreams != 17 || config.MaxIncomingUniStreams >= 0 {
		t.Fatalf("stream limits = bidi %d uni %d", config.MaxIncomingStreams, config.MaxIncomingUniStreams)
	}
	if config.InitialStreamReceiveWindow != 64<<10 || config.MaxStreamReceiveWindow != 2<<20 {
		t.Fatalf("stream windows = %d/%d", config.InitialStreamReceiveWindow, config.MaxStreamReceiveWindow)
	}
	if config.InitialConnectionReceiveWindow != 256<<10 || config.MaxConnectionReceiveWindow != 8<<20 {
		t.Fatalf("connection windows = %d/%d", config.InitialConnectionReceiveWindow, config.MaxConnectionReceiveWindow)
	}
	if config.Allow0RTT || !config.EnableDatagrams {
		t.Fatal("raw QUIC must disable 0-RTT and enable native datagrams")
	}
	if config.InitialPacketSize != MinimumInitialPacketSize {
		t.Fatalf("initial packet size = %d, want %d for a 1280-byte IP path", config.InitialPacketSize, MinimumInitialPacketSize)
	}
	if !config.EnableStreamResetPartialDelivery {
		t.Fatal("raw QUIC must negotiate native stream reset support")
	}
	if config.Tracer == nil {
		t.Fatal("raw QUIC must expose native qlog when QLOGDIR is set")
	}
	t.Setenv("QLOGDIR", t.TempDir())
	if trace := config.Tracer(context.Background(), true, quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4})); trace != nil {
		t.Fatal("raw QUIC exposed qlog outside a release evidence run")
	}
	t.Setenv("FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE", "1")
	trace := config.Tracer(context.Background(), true, quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4}))
	if trace == nil {
		t.Fatal("raw QUIC did not expose qlog during a release evidence run")
	}
	if err := trace.AddProducer().Close(); err != nil {
		t.Fatal(err)
	}
}
