package rpc

import (
	"encoding/json"
	"errors"
	"io"

	rpcv1 "github.com/flowersec/flowersec/gen/flowersec/rpc/v1"
)

var ErrBadStreamHello = errors.New("bad stream hello")

func WriteStreamHello(w io.Writer, kind string) error {
	return WriteJSONFrame(w, rpcv1.StreamHello{Kind: kind, V: 1})
}

func ReadStreamHello(r io.Reader, maxLen int) (rpcv1.StreamHello, error) {
	b, err := ReadJSONFrame(r, maxLen)
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
