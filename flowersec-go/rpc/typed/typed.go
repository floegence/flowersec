package typed

import (
	"context"
	"encoding/json"

	rpcwirev1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

type Caller interface {
	Call(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcwirev1.RpcError, error)
}

type Notifier interface {
	Notify(typeID uint32, payload json.RawMessage) error
}

// Call performs an RPC request with JSON encoding and returns a typed response.
func Call[TReq any, TResp any](ctx context.Context, c Caller, typeID uint32, req *TReq) (*TResp, error) {
	var zeroReq TReq
	if req == nil {
		req = &zeroReq
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	payload, rpcErr, err := c.Call(ctx, typeID, b)
	if err != nil {
		return nil, err
	}
	if rpcErr != nil {
		return nil, rpc.NewCallError(typeID, rpcErr)
	}
	var resp TResp
	if len(payload) != 0 {
		if err := json.Unmarshal(payload, &resp); err != nil {
			return nil, err
		}
	}
	return &resp, nil
}

// Notify sends a one-way notification with a typed JSON payload.
func Notify[T any](n Notifier, typeID uint32, msg *T) error {
	var zero T
	if msg == nil {
		msg = &zero
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return n.Notify(typeID, b)
}

// Register registers a typed request handler for the given type ID.
func Register[TReq any, TResp any](r *rpc.Router, typeID uint32, h func(ctx context.Context, req *TReq) (*TResp, error)) {
	r.Register(typeID, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcwirev1.RpcError) {
		var req TReq
		if len(payload) != 0 {
			if err := json.Unmarshal(payload, &req); err != nil {
				return nil, rpc.ToWireError(&rpc.Error{Code: 400, Message: "invalid payload"})
			}
		}
		resp, err := h(ctx, &req)
		if err != nil {
			return nil, rpc.ToWireError(err)
		}
		var zeroResp TResp
		if resp == nil {
			resp = &zeroResp
		}
		b, err := json.Marshal(resp)
		if err != nil {
			return nil, rpc.ToWireError(err)
		}
		return b, nil
	})
}
