package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

// Connect auto-detects tunnel vs direct connect inputs and returns an RPC-ready client session.
//
// Supported input types:
//   - *controlv1.ChannelInitGrant (tunnel grant, role=client)
//   - *directv1.DirectConnectInfo (direct connect info)
//   - io.Reader / []byte / string containing JSON (wrapper {"grant_client":{...}} or DirectConnectInfo)
func Connect(ctx context.Context, input any, origin string, opts ...ConnectOption) (Client, error) {
	switch v := input.(type) {
	case *controlv1.ChannelInitGrant:
		return ConnectTunnel(ctx, v, origin, opts...)
	case controlv1.ChannelInitGrant:
		cp := v
		return ConnectTunnel(ctx, &cp, origin, opts...)
	case *directv1.DirectConnectInfo:
		return ConnectDirect(ctx, v, origin, opts...)
	case directv1.DirectConnectInfo:
		cp := v
		return ConnectDirect(ctx, &cp, origin, opts...)
	case io.Reader:
		if v == nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
		}
		b, err := readAllLimit(v, protocolio.DefaultMaxJSONBytes)
		if err != nil {
			return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		return connectJSONBytes(ctx, b, origin, opts...)
	case []byte:
		return connectJSONBytes(ctx, v, origin, opts...)
	case string:
		return connectJSONBytes(ctx, []byte(v), origin, opts...)
	default:
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}
}

func connectJSONBytes(ctx context.Context, b []byte, origin string, opts ...ConnectOption) (Client, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
	}

	if _, ok := obj["ws_url"]; ok {
		var info directv1.DirectConnectInfo
		if err := json.Unmarshal(b, &info); err != nil {
			return nil, wrapErr(fserrors.PathDirect, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
		return ConnectDirect(ctx, &info, origin, opts...)
	}

	_, hasGrantClient := obj["grant_client"]
	_, hasGrantServer := obj["grant_server"]
	_, hasTunnelURL := obj["tunnel_url"]
	_, hasToken := obj["token"]
	_, hasRole := obj["role"]
	if !hasGrantClient && !hasTunnelURL && !hasToken && !hasRole {
		if hasGrantServer {
			raw := bytes.TrimSpace(obj["grant_server"])
			if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
				return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingGrant, ErrMissingGrant)
			}
			var grant controlv1.ChannelInitGrant
			if err := json.Unmarshal(raw, &grant); err != nil {
				return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
			}
			return ConnectTunnel(ctx, &grant, origin, opts...)
		}
		return nil, wrapErr(fserrors.PathAuto, fserrors.StageValidate, fserrors.CodeInvalidInput, ErrInvalidInput)
	}

	var grant controlv1.ChannelInitGrant
	if hasGrantClient {
		raw := bytes.TrimSpace(obj["grant_client"])
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeMissingGrant, ErrMissingGrant)
		}
		if err := json.Unmarshal(raw, &grant); err != nil {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
	} else {
		if err := json.Unmarshal(b, &grant); err != nil {
			return nil, wrapErr(fserrors.PathTunnel, fserrors.StageValidate, fserrors.CodeInvalidInput, err)
		}
	}
	return ConnectTunnel(ctx, &grant, origin, opts...)
}

func readAllLimit(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, protocolio.ErrInputTooLarge
	}
	return b, nil
}
