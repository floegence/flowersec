package flowersec_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

// This compile contract keeps listener registration carrier-neutral. Concrete
// adapters own their native listener lifecycle; Acceptor owns admission and
// SessionHandlers/OnSession dispatch for every registered tuple.
func TestAcceptorListenerRegistrationPublicContract(t *testing.T) {
	var listeners []flowersec.AcceptorListener
	listeners = append(listeners,
		flowersec.NewWebSocketAcceptorListener(flowersec.AcceptorPathDirect),
		flowersec.NewWebSocketAcceptorListener(flowersec.AcceptorPathTunnel),
	)
	_ = flowersec.AcceptorOptions{
		Listeners: listeners,
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	}
	var _ http.Handler = (&flowersec.Acceptor{}).Handler()
	var _ = flowersec.NewRawQUICAcceptorListener
	var _ = flowersec.NewWebTransportAcceptorListener
	var _ = (*flowersec.Acceptor).Serve
	var _ interface {
		Address() string
		Close() error
	} = listeners[0]
	_ = &tls.Config{}
}

func TestNativeAcceptorListenerOwnershipContract(t *testing.T) {
	serverTLS, _ := acceptorListenerTLS(t)
	listener, err := flowersec.NewRawQUICAcceptorListener(flowersec.RawQUICAcceptorListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS, Path: flowersec.AcceptorPathDirect,
	})
	if err != nil {
		t.Fatal(err)
	}
	if listener.Address() == "" {
		t.Fatal("native listener did not expose its bound address")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close() = %v, want idempotent success", err)
	}
}
