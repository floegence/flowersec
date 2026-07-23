package webtransport

import "testing"

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
	if config.MaxIncomingStreams != 130 || config.MaxIncomingUniStreams != MaxH3IncomingUniStreams {
		t.Fatalf("stream limits = bidi %d uni %d", config.MaxIncomingStreams, config.MaxIncomingUniStreams)
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
