package transportsecurity

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/fserrors"
)

func TestEvaluateNilPolicyRequiresTLS(t *testing.T) {
	_, err := Evaluate(context.Background(), "ws://127.0.0.1/ws", fserrors.PathDirect, RuntimeNative, nil)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Evaluate nil policy error = %v, want ErrDenied", err)
	}

	if _, err := Evaluate(context.Background(), "wss://service.example/ws", fserrors.PathDirect, RuntimeNative, nil); err != nil {
		t.Fatalf("Evaluate TLS with nil policy: %v", err)
	}
}
