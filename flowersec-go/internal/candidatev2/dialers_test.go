package candidatev2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	gorillaws "github.com/gorilla/websocket"
)

func TestWebSocketAdmissionCloseIsIdempotentAfterDialCancellation(t *testing.T) {
	accepted := make(chan *gorillaws.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		conn, err := (&gorillaws.Upgrader{}).Upgrade(response, request, nil)
		if err != nil {
			t.Errorf("upgrade WebSocket: %v", err)
			return
		}
		accepted <- conn
	}))
	t.Cleanup(server.Close)

	client, _, err := gorillaws.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	t.Cleanup(func() { _ = peer.Close() })

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	handle := &webSocketAdmissionHandle{conn: client}
	if err := handle.Close(context.Background()); err != nil {
		t.Fatalf("close canceled WebSocket admission: %v", err)
	}
}

type optionalCarrierSession struct{}

func (*optionalCarrierSession) Kind() carrier.Kind         { return carrier.KindWebTransport }
func (*optionalCarrierSession) Path() carrier.Path         { return carrier.PathDirect }
func (*optionalCarrierSession) MaxIncomingStreams() uint16 { return 1 }
func (*optionalCarrierSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (*optionalCarrierSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("unused")
}
func (*optionalCarrierSession) Termination() <-chan struct{} { return make(chan struct{}) }
func (*optionalCarrierSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return nil
}
func (*optionalCarrierSession) CloseWithError(carrier.ApplicationError) error { return nil }
func (*optionalCarrierSession) Abort(carrier.ApplicationError) error          { return nil }
func (*optionalCarrierSession) Close() error                                  { return nil }
func (*optionalCarrierSession) UnreliableAvailable() bool                     { return true }
func (*optionalCarrierSession) SendUnreliable([]byte) error                   { return nil }
func (*optionalCarrierSession) ReceiveUnreliable(context.Context) ([]byte, error) {
	return []byte("ok"), nil
}

func TestOwnedCarrierSessionPreservesOptionalUnreliableTransport(t *testing.T) {
	owned := &ownedCarrierSession{
		Session: &optionalCarrierSession{},
		owner:   carrierSessionOwnerStub{},
	}
	var transport carrier.UnreliableTransport = owned
	if !transport.UnreliableAvailable() {
		t.Fatal("owned carrier session dropped negotiated unreliable capability")
	}
	if err := transport.SendUnreliable([]byte("payload")); err != nil {
		t.Fatalf("forward unreliable send: %v", err)
	}
	payload, err := transport.ReceiveUnreliable(context.Background())
	if err != nil || string(payload) != "ok" {
		t.Fatalf("forward unreliable receive = %q, %v", payload, err)
	}
}

type carrierSessionOwnerStub struct{}

func (carrierSessionOwnerStub) CloseLocal() error { return nil }
func (carrierSessionOwnerStub) Close() error      { return nil }
