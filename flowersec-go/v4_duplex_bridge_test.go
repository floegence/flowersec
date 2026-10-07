package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// Embedding Stream does not provide the original SDK slot, queue or receive
// owner. Constructors must reject it without invoking any replacement method.
type foreignDuplexStream struct {
	Stream
	calls int
}

func (s *foreignDuplexStream) Read([]byte) (int, error)  { s.calls++; panic("foreign read") }
func (s *foreignDuplexStream) Write([]byte) (int, error) { s.calls++; panic("foreign write") }

func TestPublicDuplexBridgeRejectsSubstituteOwnersBeforeIO(t *testing.T) {
	a, b := &foreignDuplexStream{}, &foreignDuplexStream{}
	if bridge, err := NewDuplexBridge(context.Background(), a, b, DuplexBridgeOptions{}); bridge != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(bridge, err)
	}
	if bridge, err := NewNativeDuplexBridge(context.Background(), a, &NativeTCP{}, DuplexBridgeOptions{}); bridge != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(bridge, err)
	}
	if a.calls != 0 || b.calls != 0 {
		t.Fatal("constructor invoked substitute I/O")
	}
	var missing *v4Stream
	if bridge, err := NewDuplexBridge(context.Background(), missing, missing, DuplexBridgeOptions{}); bridge != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(bridge, err)
	}
}

func TestPublicDuplexOwnerlessHandlesCannotInventCompletion(t *testing.T) {
	var bridge *DuplexBridge
	if bridge.Start() != ErrOperationClosed || bridge.CleanupStatus().Complete {
		t.Fatal("missing owner claimed completion")
	}
	if result, err := bridge.Wait(context.Background()); err != ErrOperationClosed || result.Result != nil {
		t.Fatal(result, err)
	}
	bridge.Abort()
	var dial *NativeTCPDial
	dial.Cancel()
	if native, err := dial.Wait(context.Background()); err != ErrOperationClosed || native != nil || dial.CleanupStatus().Complete {
		t.Fatal(native, err)
	}
	var native *NativeTCP
	if native.Close() != ErrOperationClosed || native.CleanupStatus().Complete {
		t.Fatal("missing native owner claimed close")
	}
}
