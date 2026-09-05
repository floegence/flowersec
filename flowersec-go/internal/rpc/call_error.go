package rpc

import (
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v5/internal/rpcwire"
)

// RemoteError is the sanitized application error returned by a remote RPC handler.
type RemoteError = rpcv1.RpcError

// CallError represents an RPC-layer error returned in a response envelope.
// Transport errors are returned as regular Go errors by the underlying client.
type CallError struct {
	TypeID  uint32
	Code    uint32
	Message *string
}

func (e *CallError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != nil && *e.Message != "" {
		return *e.Message
	}
	return "rpc error"
}

// NewCallError converts a wire RpcError into a typed Go error.
func NewCallError(typeID uint32, rpcErr *rpcv1.RpcError) error {
	if rpcErr == nil {
		return nil
	}
	return &CallError{
		TypeID:  typeID,
		Code:    rpcErr.Code,
		Message: rpcErr.Message,
	}
}
