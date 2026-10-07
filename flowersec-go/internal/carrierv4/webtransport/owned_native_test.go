package webtransport

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type nativeConnectStreamFixture struct{ *quic.Stream }

func (nativeConnectStreamFixture) SendDatagram([]byte) error { return nil }
func (nativeConnectStreamFixture) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestOwnedNativeStripsOriginalConnectAssociation(t *testing.T) {
	serverTLS, clientTLS := tupleTLS(t)
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	limits := quicbase.DefaultLimits()
	serverConfig, err := newServerQUICConfig(limits)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConfig, err := newQUICConfig(limits)
	if err != nil {
		t.Fatal(err)
	}
	client, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	connect, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A QUIC stream becomes observable to the peer once it carries a frame.
	// Use an empty native capsule to announce the synthetic CONNECT stream.
	if _, err := connect.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	request, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	o := OwnedOptions{Limits: limits, StreamSlots: 8}
	session := newOwnedNativeSession(server, o, false)
	if err := session.install(nativeConnectStreamFixture{Stream: request}); err != nil {
		t.Fatal(err)
	}
	session.start(nil, nil)
	t.Cleanup(func() {
		_ = session.Close()
		select {
		case <-session.done:
		case <-time.After(2 * time.Second):
			t.Error("associated session did not stop")
		}
		_ = connect.Close()
	})

	raw, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(append(quicvarint.Append(quicvarint.Append(nil, 0x41), uint64(connect.StreamID())), 'F')); err != nil {
		t.Fatal(err)
	}
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer acceptCancel()
	stream, err := session.AcceptStream(acceptCtx)
	if err != nil {
		t.Fatalf("accepted associated stream before payload completion: %v", err)
	}
	if _, err := raw.Write([]byte("SB4")); err != nil {
		t.Fatal(err)
	}
	var first [4]byte
	if _, err := io.ReadFull(stream, first[:]); err != nil {
		t.Fatal(err)
	}
	if string(first[:]) != "FSB4" {
		t.Fatalf("associated stream exposed its transport prefix: %q", first[:])
	}
}

func TestOriginPolicyDoesNotDowngradeCarrierTLS(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:8080", "http://[::1]:8080", "https://app.example"} {
		if err := validateOrigin(origin); err != nil {
			t.Fatalf("valid document origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{"file://host", "https://user@app.example", "https://app.example/path", "https://app.example?query=1"} {
		if validateOrigin(origin) == nil {
			t.Fatalf("invalid document origin %q accepted", origin)
		}
	}
	if ValidateURL("http://127.0.0.1:8080"+PathDirect) == nil {
		t.Fatal("document origin policy allowed plaintext WebTransport")
	}
}
