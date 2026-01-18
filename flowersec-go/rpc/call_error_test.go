package rpc

import (
	"testing"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
)

func TestNewCallError(t *testing.T) {
	msg := "boom"
	err := NewCallError(7, &rpcv1.RpcError{Code: 123, Message: &msg})
	ce, ok := err.(*CallError)
	if !ok {
		t.Fatalf("expected *CallError, got %T", err)
	}
	if ce.TypeID != 7 {
		t.Fatalf("TypeID=%d, want 7", ce.TypeID)
	}
	if ce.Code != 123 {
		t.Fatalf("Code=%d, want 123", ce.Code)
	}
	if ce.Message != msg {
		t.Fatalf("Message=%q, want %q", ce.Message, msg)
	}
	if ce.Error() != msg {
		t.Fatalf("Error()=%q, want %q", ce.Error(), msg)
	}
}
