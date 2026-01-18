package streamhello

import (
	"encoding/json"
	"errors"
	"io"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc/frame"
)

var ErrBadStreamHello = errors.New("bad stream hello")

// WriteStreamHello sends a simple protocol greeting with the stream kind.
func WriteStreamHello(w io.Writer, kind string) error {
	return frame.WriteJSONFrame(w, rpcv1.StreamHello{Kind: kind, V: 1})
}

// ReadStreamHello reads and validates the stream greeting.
func ReadStreamHello(r io.Reader, maxLen int) (rpcv1.StreamHello, error) {
	b, err := frame.ReadJSONFrame(r, maxLen)
	if err != nil {
		return rpcv1.StreamHello{}, err
	}
	var h rpcv1.StreamHello
	if err := json.Unmarshal(b, &h); err != nil {
		return rpcv1.StreamHello{}, ErrBadStreamHello
	}
	if h.V != 1 || h.Kind == "" {
		return rpcv1.StreamHello{}, ErrBadStreamHello
	}
	return h, nil
}
