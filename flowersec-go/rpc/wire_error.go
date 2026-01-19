package rpc

import (
	"errors"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
)

// Error is a server-side RPC error that can be returned by generated handlers.
//
// It is converted into a wire RpcError and sent back to the caller.
type Error struct {
	Code    uint32
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return "rpc error"
}

// ToWireError maps an error into a wire RpcError.
//
// If err is (or wraps) *rpc.Error, its Code/Message are used. Any other error is
// treated as an internal error (code=500, message="internal error").
func ToWireError(err error) *rpcv1.RpcError {
	if err == nil {
		return nil
	}
	var re *Error
	if errors.As(err, &re) && re != nil {
		code := re.Code
		if code == 0 {
			code = 500
		}
		msg := re.Message
		if msg == "" {
			msg = "rpc error"
		}
		return &rpcv1.RpcError{Code: code, Message: &msg}
	}
	msg := "internal error"
	return &rpcv1.RpcError{Code: 500, Message: &msg}
}
