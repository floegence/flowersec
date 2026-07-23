package carrier_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

type testStream struct{}

func (testStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (testStream) Write(p []byte) (int, error) { return len(p), nil }
func (testStream) CloseWrite() error           { return nil }
func (testStream) Reset() error                { return nil }
func (testStream) Close() error                { return nil }
func (testStream) Context() context.Context    { return context.Background() }

type testSession struct{}

func (testSession) Kind() carrier.Kind         { return carrier.KindQUIC }
func (testSession) Path() carrier.Path         { return carrier.PathDirect }
func (testSession) MaxIncomingStreams() uint16 { return 130 }
func (testSession) OpenStream(context.Context) (carrier.Stream, error) {
	return testStream{}, nil
}
func (testSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return testStream{}, nil
}
func (testSession) CloseWithError(carrier.ApplicationError) error { return nil }
func (testSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return nil
}
func (testSession) Close() error { return nil }

func TestCarrierContractIsTransportNeutral(t *testing.T) {
	var _ carrier.Stream = testStream{}
	var _ carrier.Session = testSession{}

	for _, kind := range []carrier.Kind{
		carrier.KindWebSocket,
		carrier.KindQUIC,
		carrier.KindWebTransport,
	} {
		if err := kind.Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", kind, err)
		}
	}
	if err := carrier.Kind("yamux").Validate(); !errors.Is(err, carrier.ErrInvalidKind) {
		t.Fatalf("invalid carrier error = %v, want ErrInvalidKind", err)
	}
	for _, path := range []carrier.Path{carrier.PathDirect, carrier.PathTunnel} {
		if err := path.Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", path, err)
		}
	}
	if err := carrier.Path("other").Validate(); !errors.Is(err, carrier.ErrInvalidPath) {
		t.Fatalf("invalid carrier path error = %v, want ErrInvalidPath", err)
	}
}

func TestApplicationErrorIsBoundedAndGeneric(t *testing.T) {
	err := carrier.ApplicationError{Code: 7, Reason: "stream_reset"}
	if err.Code != 7 || err.Reason != "stream_reset" {
		t.Fatalf("unexpected application error: %+v", err)
	}
	if carrier.MaxApplicationErrorReasonBytes != 128 {
		t.Fatalf("MaxApplicationErrorReasonBytes = %d", carrier.MaxApplicationErrorReasonBytes)
	}
}

func TestRequiredIncomingStreamsReservesControlAndRPC(t *testing.T) {
	for _, test := range []struct {
		logical uint16
		want    uint16
	}{
		{logical: 1, want: 3},
		{logical: 128, want: 130},
	} {
		got, err := carrier.RequiredIncomingStreams(test.logical)
		if err != nil || got != test.want {
			t.Fatalf("RequiredIncomingStreams(%d) = %d, %v, want %d", test.logical, got, err, test.want)
		}
	}
	for _, invalid := range []uint16{0, 129} {
		if _, err := carrier.RequiredIncomingStreams(invalid); !errors.Is(err, carrier.ErrInvalidStreamCapacity) {
			t.Fatalf("RequiredIncomingStreams(%d) error = %v", invalid, err)
		}
	}
}
