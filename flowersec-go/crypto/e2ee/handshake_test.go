package e2ee

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type stubTransport struct {
	readCalled  bool
	writeCalled bool
}

func (t *stubTransport) ReadBinary(_ context.Context) ([]byte, error) {
	t.readCalled = true
	return nil, errors.New("unexpected read")
}

func (t *stubTransport) WriteBinary(_ context.Context, _ []byte) error {
	t.writeCalled = true
	return errors.New("unexpected write")
}

func (t *stubTransport) Close() error {
	return nil
}

func TestServerHandshakeRequiresInitExp(t *testing.T) {
	transport := &stubTransport{}
	_, err := ServerHandshake(context.Background(), transport, nil, ServerHandshakeOptions{PSK: make([]byte, 32), InitExpireAtUnixS: 0})
	if err == nil || err.Error() != "missing init_exp" {
		t.Fatalf("expected missing init_exp error, got %v", err)
	}
	if transport.readCalled || transport.writeCalled {
		t.Fatalf("unexpected transport usage: read=%v write=%v", transport.readCalled, transport.writeCalled)
	}
}

func TestHandshakeServerFinishedPingRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	clientTr, serverTr := newMemoryTransportPair(8)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cache := NewServerHandshakeCache()
	serverCh := make(chan *SecureChannel, 1)
	serverErr := make(chan error, 1)
	go func() {
		sc, err := ServerHandshake(ctx, serverTr, cache, ServerHandshakeOptions{
			PSK:                 psk,
			Suite:               SuiteX25519HKDFAES256GCM,
			ChannelID:           "chan_test",
			InitExpireAtUnixS:   time.Now().Add(60 * time.Second).Unix(),
			ClockSkew:           30 * time.Second,
			ServerFeatures:      1,
			MaxHandshakePayload: 8 * 1024,
			MaxRecordBytes:      1 << 20,
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverCh <- sc
	}()

	cc, err := ClientHandshake(ctx, clientTr, ClientHandshakeOptions{
		PSK:                 psk,
		Suite:               SuiteX25519HKDFAES256GCM,
		ChannelID:           "chan_test",
		ClientFeatures:      0,
		MaxHandshakePayload: 8 * 1024,
		MaxRecordBytes:      1 << 20,
	})
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	defer cc.Close()

	var sc *SecureChannel
	select {
	case sc = <-serverCh:
	case err := <-serverErr:
		t.Fatalf("server handshake failed: %v", err)
	case <-ctx.Done():
		t.Fatalf("timeout waiting for server handshake: %v", ctx.Err())
	}
	defer sc.Close()

	serverMsg := []byte("server->client")
	if n, err := sc.Write(serverMsg); err != nil || n != len(serverMsg) {
		t.Fatalf("server write failed: n=%d err=%v", n, err)
	}
	gotServer := make([]byte, len(serverMsg))
	if _, err := io.ReadFull(cc, gotServer); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if !bytes.Equal(gotServer, serverMsg) {
		t.Fatalf("server->client mismatch: got=%q want=%q", gotServer, serverMsg)
	}

	clientMsg := []byte("client->server")
	if n, err := cc.Write(clientMsg); err != nil || n != len(clientMsg) {
		t.Fatalf("client write failed: n=%d err=%v", n, err)
	}
	gotClient := make([]byte, len(clientMsg))
	if _, err := io.ReadFull(sc, gotClient); err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if !bytes.Equal(gotClient, clientMsg) {
		t.Fatalf("client->server mismatch: got=%q want=%q", gotClient, clientMsg)
	}
}
