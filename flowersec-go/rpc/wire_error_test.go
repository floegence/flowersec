package rpc_test

import (
	"errors"
	"fmt"
	"testing"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

func TestToWireError_Nil(t *testing.T) {
	if rpc.ToWireError(nil) != nil {
		t.Fatalf("expected nil")
	}
}

func TestToWireError_RPCErr(t *testing.T) {
	got := rpc.ToWireError(&rpc.Error{Code: 400, Message: "bad request"})
	if got == nil {
		t.Fatalf("expected error")
	}
	if got.Code != 400 {
		t.Fatalf("unexpected code: %d", got.Code)
	}
	if got.Message == nil || *got.Message != "bad request" {
		t.Fatalf("unexpected message: %#v", got.Message)
	}
}

func TestToWireError_RPCErrWrapped(t *testing.T) {
	err := fmt.Errorf("wrap: %w", &rpc.Error{Code: 401, Message: "unauthorized"})
	got := rpc.ToWireError(err)
	if got == nil {
		t.Fatalf("expected error")
	}
	if got.Code != 401 {
		t.Fatalf("unexpected code: %d", got.Code)
	}
	if got.Message == nil || *got.Message != "unauthorized" {
		t.Fatalf("unexpected message: %#v", got.Message)
	}
}

func TestToWireError_Defaults(t *testing.T) {
	got := rpc.ToWireError(&rpc.Error{})
	if got == nil {
		t.Fatalf("expected error")
	}
	if got.Code != 500 {
		t.Fatalf("unexpected code: %d", got.Code)
	}
	if got.Message == nil || *got.Message != "rpc error" {
		t.Fatalf("unexpected message: %#v", got.Message)
	}
}

func TestToWireError_Internal(t *testing.T) {
	got := rpc.ToWireError(errors.New("boom"))
	if got == nil {
		t.Fatalf("expected error")
	}
	if got.Code != 500 {
		t.Fatalf("unexpected code: %d", got.Code)
	}
	if got.Message == nil || *got.Message != "internal error" {
		t.Fatalf("unexpected message: %#v", got.Message)
	}
	// Ensure the return type matches the wire struct.
	_ = (*rpcv1.RpcError)(got)
}
