package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	fs "github.com/floegence/flowersec/flowersec-go/v7"
)

const capacityEchoID = 7011
const capacityRawKind = "public-release-roundtrip"
const capacityLarge = 1 << 20

func capacityBusinessFrame() fs.RPCFrameLimits {
	return fs.RPCFrameLimits{ReadBytes: capacityLarge + 256, WriteBytes: capacityLarge + 256}
}

func capacitySize(size int) bool { return size == 256 || size == capacityLarge }

type capacityStreamOwner struct{}

func resetCapacityStreamOnCancel(ctx context.Context, stream fs.ByteStream) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = stream.Reset()
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

func capacityWrite(stream fs.ByteStream, data []byte) error {
	written, err := stream.Write(data)
	if err == nil && written != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (d *capacityProduct) registerCapacityBusiness(r registrar, handleStream func(string, fs.StreamHandler) error) error {
	if err := r.HandleRPC(capacityEchoID, func(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) {
		if _, allowed := d.permitted(ctx, 1); !allowed {
			return nil, bad(403)
		}
		var payload string
		if len(raw) > capacityLarge+2 || json.Unmarshal(raw, &payload) != nil || !capacitySize(len(payload)) || strings.Count(payload, "Z") != len(payload) {
			return nil, bad(400)
		}
		return payload, nil
	}); err != nil {
		return err
	}
	return handleStream(capacityRawKind, func(ctx context.Context, in fs.IncomingStream) error {
		if d.opts.ServerCarrier != "" {
			owner, _ := ctx.Value(capacityStreamOwner{}).(*capacityPair)
			if !d.hasGrant(owner, 1) {
				return errCapacityConfiguration
			}
		}
		if in.Kind != capacityRawKind || in.Metadata.Values()["direction"] != "client-to-server" {
			return errCapacityConfiguration
		}
		defer resetCapacityStreamOnCancel(ctx, in.Stream)()
		request, err := io.ReadAll(io.LimitReader(in.Stream, capacityLarge+1))
		if err != nil {
			return err
		}
		if !capacitySize(len(request)) || bytes.Count(request, []byte{0x5a}) != len(request) {
			return errCapacityConfiguration
		}
		return capacityWrite(in.Stream, bytes.Repeat([]byte{0x37}, len(request)))
	})
}

func (d *capacityProduct) capacityBusiness(ctx context.Context, p *capacityPair, r capacityRequest) (any, error) {
	if p == nil || p.generation != 1 || !p.live.Load() || p.closing.Load() || !capacitySize(r.Bytes) {
		return nil, errCapacityConfiguration
	}
	p.mu.Lock()
	client := p.ends[0]
	p.mu.Unlock()
	if client == nil {
		return nil, errCapacityConfiguration
	}
	switch r.Operation {
	case "echo":
		request := strings.Repeat("Z", r.Bytes)
		var reply string
		if err := client.RPC().Call(ctx, capacityEchoID, request, &reply); err != nil {
			return nil, err
		}
		if reply != request {
			return nil, errors.New("capacity RPC echo mismatch")
		}
	case "raw":
		meta, err := fs.NewStreamMetadata(map[string]any{"direction": "client-to-server"})
		if err != nil {
			return nil, err
		}
		stream, err := client.OpenStream(ctx, capacityRawKind, meta)
		if err != nil {
			return nil, err
		}
		defer resetCapacityStreamOnCancel(ctx, stream)()
		completed := false
		defer func() {
			if !completed {
				_ = stream.Reset()
			}
		}()
		if err = capacityWrite(stream, bytes.Repeat([]byte{0x5a}, r.Bytes)); err != nil {
			return nil, err
		}
		if err = stream.CloseWrite(); err != nil {
			return nil, err
		}
		reply, err := io.ReadAll(io.LimitReader(stream, int64(r.Bytes)+1))
		if err != nil {
			return nil, err
		}
		if len(reply) != r.Bytes || bytes.Count(reply, []byte{0x37}) != r.Bytes {
			return nil, errors.New("capacity raw response mismatch")
		}
		if err = stream.Close(); err != nil {
			return nil, err
		}
		completed = true
	default:
		return nil, errCapacityConfiguration
	}
	return map[string]any{"id": p.id, "generation": p.generation, "operation": r.Operation, "requestBytes": r.Bytes, "responseBytes": r.Bytes, "verified": true}, nil
}
