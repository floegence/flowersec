package e2ee

import (
	"context"
	"errors"
	"testing"
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
	_, err := ServerHandshake(context.Background(), transport, nil, HandshakeOptions{
		PSK:               make([]byte, 32),
		InitExpireAtUnixS: 0,
	})
	if err == nil || err.Error() != "missing init_exp" {
		t.Fatalf("expected missing init_exp error, got %v", err)
	}
	if transport.readCalled || transport.writeCalled {
		t.Fatalf("unexpected transport usage: read=%v write=%v", transport.readCalled, transport.writeCalled)
	}
}
