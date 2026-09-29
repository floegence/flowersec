package sessionv4

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type initialFailedStream struct{ err error }

func (p initialFailedStream) Read([]byte) (int, error)                         { return 0, p.err }
func (p initialFailedStream) Write([]byte) (int, error)                        { return 0, p.err }
func (initialFailedStream) Close() error                                       { return nil }
func (p initialFailedStream) ReadMessage(context.Context, []byte) (int, error) { return 0, p.err }
func (p initialFailedStream) WriteMessage(context.Context, []byte) error       { return p.err }

type initialEOFStream struct{ initialMemoryStream }

func (p *initialEOFStream) Read(dst []byte) (int, error) {
	n, err := p.initialMemoryStream.Read(dst)
	if p.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

type initialFixtureMessages struct {
	initialFailedStream
	wire []byte
}

func (p initialFixtureMessages) ReadMessage(_ context.Context, dst []byte) (int, error) {
	return copy(dst, p.wire), nil
}

func TestInitialTransportFailureRequiresActualProviderCall(t *testing.T) {
	for _, message := range []bool{false, true} {
		for _, origin := range []string{"read", "write", "builder", "verifier", "closed", "protocol"} {
			t.Run(origin+map[bool]string{false: "/stream", true: "/message"}[message], func(t *testing.T) {
				config := initialTestConfig(t, protocolv4.ClientToServer, protocolv4.DHProfileX25519)
				if origin == "read" || origin == "verifier" {
					config.Role = protocolv4.ServerToClient
				}
				p := initialFailedStream{err: native.ErrConnectionLost}
				var x *InitialExchange
				var err error
				if origin == "verifier" {
					wire, _ := (protocolv4.Envelope{FrameType: protocolv4.FrameNegotiate, Payload: initialFixture(t, "client_hello_fields")}).Encode()
					if message {
						x, err = NewInitialMessages(context.Background(), config, initialFixtureMessages{wire: wire})
					} else {
						x, err = NewInitialStream(context.Background(), config, &initialMemoryStream{Buffer: *bytes.NewBuffer(wire)})
					}
				} else if message {
					x, err = NewInitialMessages(context.Background(), config, p)
				} else {
					x, err = NewInitialStream(context.Background(), config, p)
				}
				if err != nil {
					t.Fatal(err)
				}
				cleanupInitial(t, x)
				switch origin {
				case "closed":
					x.Close(cryptov4.ErrClosed)
				case "protocol":
					x.Close(ErrInitialPhase)
				}
				if origin == "read" {
					err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { t.Error("verification after failed input"); return nil })
				} else if origin == "verifier" {
					err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { return native.ErrConnectionLost })
				} else {
					build := initialCopy(initialFixture(t, "client_hello_fields"))
					if origin == "builder" {
						build = func([]byte) (int, error) { return 0, native.ErrConnectionLost }
					}
					_, err = x.Send(protocolv4.FrameNegotiate, build)
				}
				if err == nil {
					t.Fatal("failure lost")
				}
				x.mu.Lock()
				retry := x.transportFailure
				x.mu.Unlock()
				if retry != (origin == "read" || origin == "write") {
					t.Fatal("failure origin changed", origin, retry)
				}
			})
		}
	}
}

func TestInitialProviderEOFStillCompletesExactInput(t *testing.T) {
	wire, _ := (protocolv4.Envelope{FrameType: protocolv4.FrameNegotiate, Payload: initialFixture(t, "client_hello_fields")}).Encode()
	p := &initialEOFStream{initialMemoryStream{Buffer: *bytes.NewBuffer(wire)}}
	x, err := NewInitialStream(context.Background(), initialTestConfig(t, protocolv4.ServerToClient, protocolv4.DHProfileX25519), p)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	verified := false
	if err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { verified = true; return nil }); err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	retry := x.transportFailure
	x.mu.Unlock()
	if !verified || retry {
		t.Fatal("complete input treated as truncated flight")
	}
}
