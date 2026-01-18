package rpc

import (
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
)

// CallError represents an RPC-layer error returned in a response envelope.
// Transport errors are returned as regular Go errors by the underlying client.
type CallError struct {
	TypeID  uint32
	Code    uint32
	Message string
}

func (e *CallError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return "rpc error"
}

// NewCallError converts a wire RpcError into a typed Go error.
func NewCallError(typeID uint32, rpcErr *rpcv1.RpcError) error {
	if rpcErr == nil {
		return nil
	}
	msg := ""
	if rpcErr.Message != nil {
		msg = *rpcErr.Message
	}
	return &CallError{
		TypeID:  typeID,
		Code:    rpcErr.Code,
		Message: msg,
	}
}
