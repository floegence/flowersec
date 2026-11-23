package rpcwire

import "encoding/json"

// RpcEnvelope is the private JSON framing contract used by the session RPC slot.
type RpcEnvelope struct {
	TypeId     uint32          `json:"type_id"`
	RequestId  uint64          `json:"request_id"`
	ResponseTo uint64          `json:"response_to"`
	Payload    json.RawMessage `json:"payload"`
	Error      *RpcError       `json:"error,omitempty"`
}

// Error is the private error payload carried by an Envelope.
type RpcError struct {
	Code    uint32  `json:"code"`
	Message *string `json:"message,omitempty"`
}

// StreamHello identifies the private protocol bound to a newly opened stream.
type StreamHello struct {
	Kind string `json:"kind"`
	V    uint32 `json:"v"`
}
