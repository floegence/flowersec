package rawquic

import (
	"testing"
	"time"
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
	if config.Allow0RTT || config.EnableDatagrams {
		t.Fatal("raw QUIC must not enable 0-RTT or datagrams")
	}
	if !config.EnableStreamResetPartialDelivery {
		t.Fatal("raw QUIC must negotiate native stream reset support")
	}
}
