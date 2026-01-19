package protocolio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

const DefaultMaxJSONBytes = 1 << 20

var ErrInputTooLarge = errors.New("input too large")

// DecodeGrantClientJSON decodes a ChannelInitGrant for role=client.
//
// It accepts either the raw ChannelInitGrant JSON object or a wrapper object:
// {"grant_client": {...}}.
func DecodeGrantClientJSON(r io.Reader) (*controlv1.ChannelInitGrant, error) {
	g, err := decodeGrantFromReader(r, DefaultMaxJSONBytes, "grant_client")
	if err != nil {
		return nil, err
	}
	if g.Role != controlv1.Role_client {
		return nil, fmt.Errorf("expected role=client, got %v", g.Role)
	}
	return g, nil
}

// DecodeGrantServerJSON decodes a ChannelInitGrant for role=server.
//
// It accepts either the raw ChannelInitGrant JSON object or a wrapper object:
// {"grant_server": {...}}.
func DecodeGrantServerJSON(r io.Reader) (*controlv1.ChannelInitGrant, error) {
	g, err := decodeGrantFromReader(r, DefaultMaxJSONBytes, "grant_server")
	if err != nil {
		return nil, err
	}
	if g.Role != controlv1.Role_server {
		return nil, fmt.Errorf("expected role=server, got %v", g.Role)
	}
	return g, nil
}

// DecodeGrantJSON decodes a raw ChannelInitGrant JSON object without role validation.
func DecodeGrantJSON(r io.Reader) (*controlv1.ChannelInitGrant, error) {
	b, err := readAllLimit(r, DefaultMaxJSONBytes)
	if err != nil {
		return nil, err
	}
	var g controlv1.ChannelInitGrant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// DecodeDirectConnectInfoJSON decodes a DirectConnectInfo JSON object.
func DecodeDirectConnectInfoJSON(r io.Reader) (*directv1.DirectConnectInfo, error) {
	b, err := readAllLimit(r, DefaultMaxJSONBytes)
	if err != nil {
		return nil, err
	}
	var info directv1.DirectConnectInfo
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func decodeGrantFromReader(r io.Reader, maxBytes int64, wrapperKey string) (*controlv1.ChannelInitGrant, error) {
	b, err := readAllLimit(r, maxBytes)
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	// Wrapper path.
	if raw, ok := obj[wrapperKey]; ok {
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("%s is null", wrapperKey)
		}
		var g controlv1.ChannelInitGrant
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, err
		}
		return &g, nil
	}
	// Raw object path.
	var g controlv1.ChannelInitGrant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func readAllLimit(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, ErrInputTooLarge
	}
	return b, nil
}
