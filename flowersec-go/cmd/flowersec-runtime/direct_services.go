package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/rpcwire"
	session "github.com/floegence/flowersec/flowersec-go/v7/internal/sessionv3"
)

type directServiceConfig struct {
	Slots         int                `json:"slots"`
	RPCFrameBytes int                `json:"rpc_frame_bytes"`
	Methods       []directMethodSpec `json:"methods"`
}

type directMethodSpec struct {
	Shape           string         `json:"shape"`
	TypeID          uint32         `json:"type_id,omitempty"`
	Kind            string         `json:"kind,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	Upstream        string         `json:"upstream"`
	AllowedChannels []string       `json:"allowed_channels"`
	TimeoutMS       uint32         `json:"timeout_ms"`
	MaxRequest      uint32         `json:"max_request_bytes"`
	MaxResponse     uint32         `json:"max_response_bytes,omitempty"`
	MaxItems        uint32         `json:"max_items,omitempty"`
	MaxTotal        uint32         `json:"max_stream_payload_bytes,omitempty"`
}

type directServiceHost struct {
	rpcs    map[uint32]*directMethod
	streams map[string]*directMethod
	slots   chan struct{}
	frames  int
}

type directMethod struct {
	spec     directMethodSpec
	channels map[string]bool
	metadata []byte
}

type directMethodGrant struct {
	channel string
	target  upstreamTarget
}

var directChannelID = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

func prepareDirectServices(config *directServiceConfig) (*directServiceHost, error) {
	if config == nil {
		return nil, nil
	}
	if config.Slots < 1 || config.Slots > 128 || config.RPCFrameBytes < 256 || config.RPCFrameBytes > 64<<20 || len(config.Methods) == 0 {
		return nil, &ConfigError{Field: "direct_services", Err: errors.New("requires 1 to 128 slots, rpc_frame_bytes from 256 to 67108864 and at least one method")}
	}
	host := &directServiceHost{rpcs: make(map[uint32]*directMethod), streams: make(map[string]*directMethod), slots: make(chan struct{}, config.Slots), frames: config.RPCFrameBytes}
	for index, spec := range config.Methods {
		invalid := func(reason string) error {
			return &ConfigError{Field: fmt.Sprintf("direct_services.methods[%d]", index), Err: errors.New(reason)}
		}
		addr, err := netip.ParseAddrPort(spec.Upstream)
		if err != nil || addr.String() != spec.Upstream || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || addr.Addr().Zone() != "" || addr.Addr().Is4In6() {
			return nil, invalid("upstream must be a fixed canonical unicast IP:port with a nonzero port")
		}
		if spec.TimeoutMS == 0 || spec.TimeoutMS > 300000 || spec.MaxRequest == 0 || spec.MaxRequest > 32<<20 || spec.MaxResponse > 32<<20 || len(spec.AllowedChannels) == 0 {
			return nil, invalid("requires explicit allowed channels, timeout_ms from 1 to 300000 and payload limits within 32 MiB")
		}
		method := &directMethod{spec: spec, channels: make(map[string]bool)}
		for _, channel := range spec.AllowedChannels {
			if !directChannelID.MatchString(channel) || method.channels[channel] {
				return nil, invalid("invalid or duplicate allowed channel")
			}
			method.channels[channel] = true
		}
		switch spec.Shape {
		case "unary", "notification":
			if spec.TypeID == 0 || host.rpcs[spec.TypeID] != nil || spec.Kind != "" || spec.Metadata != nil || spec.MaxItems != 0 || spec.MaxTotal != 0 || (spec.Shape == "unary") != (spec.MaxResponse != 0) || spec.MaxRequest > uint32(host.frames) || spec.MaxResponse > uint32(host.frames) {
				return nil, invalid("requires a unique nonzero RPC type_id and RPC payload limits within rpc_frame_bytes; only unary has a response")
			}
			host.rpcs[spec.TypeID] = method
		case "stream":
			if spec.TypeID != 0 || !protocolv3.ValidApplicationStreamKind(spec.Kind) || spec.Kind == "flowersec.rpc.v2" || spec.Kind == "flowersec.rpc.v5" || host.streams[spec.Kind] != nil || spec.MaxResponse == 0 || spec.MaxItems == 0 || spec.MaxTotal < spec.MaxResponse {
				return nil, invalid("requires a unique application kind, maximum item bytes, item count and total stream payload bytes")
			}
			metadata := spec.Metadata
			if metadata == nil {
				metadata = map[string]any{}
			}
			method.metadata, err = protocolv3.MarshalOpenMetadata(metadata)
			if err != nil {
				return nil, invalid("invalid OPEN metadata")
			}
			host.streams[spec.Kind] = method
		default:
			return nil, invalid("shape must be unary, notification or stream")
		}
	}
	return host, nil
}

func (method *directMethod) allows(grant directMethodGrant) bool {
	return method != nil && method.channels[grant.channel] && grant.target.Network == "tcp" && grant.target.Address == method.spec.Upstream
}

func (host *directServiceHost) acquire() bool {
	select {
	case host.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (host *directServiceHost) installRPC(config *session.Config, grant directMethodGrant) {
	slots := cap(host.slots)
	config.RPCServerOptions = rpc.ServerOptions{FrameLimits: rpc.FrameLimits{ReadBytes: host.frames, WriteBytes: host.frames}, MaxConcurrentRequests: slots, MaxQueuedRequests: slots, MaxQueuedNotifications: slots}
	config.RPCRouter = rpc.NewInboundRouter(func(ctx context.Context, id uint32, notification bool, received time.Time, payload json.RawMessage) (json.RawMessage, *rpcwire.RpcError) {
		method := host.rpcs[id]
		if !method.allows(grant) || notification != (method.spec.Shape == "notification") {
			return nil, &rpcwire.RpcError{Code: 404}
		}
		if len(payload) > int(method.spec.MaxRequest) {
			return nil, &rpcwire.RpcError{Code: 413}
		}
		if !host.acquire() {
			return nil, &rpcwire.RpcError{Code: 429}
		}
		defer func() { <-host.slots }()
		call, cancel := context.WithDeadline(ctx, received.Add(time.Duration(method.spec.TimeoutMS)*time.Millisecond))
		defer cancel()
		var response []byte
		err := method.exchange(call, payload, func(upstream io.Reader) error {
			var err error
			response, err = readMethodPayload(upstream, method.spec.MaxResponse)
			if err == nil && !notification && (!utf8.Valid(response) || !json.Valid(response)) {
				return errors.New("invalid upstream JSON")
			}
			return err
		})
		if call.Err() != nil {
			return nil, &rpcwire.RpcError{Code: 504}
		}
		if err != nil {
			return nil, &rpcwire.RpcError{Code: 502}
		}
		return response, nil
	})
}

func readMethodPayload(input io.Reader, maximum uint32) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(input, int64(maximum)+1))
	if err != nil || uint64(len(payload)) > uint64(maximum) {
		return nil, errors.New("incomplete or oversized method payload")
	}
	return payload, nil
}

func (method *directMethod) exchange(ctx context.Context, input []byte, consume func(io.Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", method.spec.Upstream)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer joinOnCancel(ctx, func() { _ = connection.Close() })()
	if _, err := io.Copy(connection, bytes.NewReader(input)); err != nil {
		return err
	}
	if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	return consume(connection)
}

func joinOnCancel(ctx context.Context, interrupt func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); interrupt() })
	return func() {
		if !stop() {
			<-done
		}
	}
}

func (host *directServiceHost) dispatchStream(ctx context.Context, grant directMethodGrant, incoming session.IncomingStream, bridges *sync.WaitGroup) {
	method := host.streams[incoming.Kind]
	if !method.allows(grant) {
		_ = incoming.Stream.Reset()
		return
	}
	metadata, err := protocolv3.MarshalOpenMetadata(incoming.Metadata)
	if err != nil || !bytes.Equal(metadata, method.metadata) || !host.acquire() {
		_ = incoming.Stream.Reset()
		return
	}
	call, cancel := context.WithTimeout(ctx, time.Duration(method.spec.TimeoutMS)*time.Millisecond)
	bridges.Go(func() {
		defer func() { <-host.slots }()
		defer cancel()
		defer joinOnCancel(call, func() { _ = incoming.Stream.Reset() })()
		input, err := readMethodPayload(incoming.Stream, method.spec.MaxRequest)
		if err == nil {
			err = method.exchange(call, input, func(upstream io.Reader) error {
				return method.copyItems(incoming.Stream, upstream)
			})
		}
		if err == nil {
			err = incoming.Stream.CloseWrite()
		}
		if err != nil {
			_ = incoming.Stream.Reset()
		}
	})
}

func (method *directMethod) copyItems(output io.Writer, upstream io.Reader) error {
	var header [4]byte
	var total uint64
	var item []byte
	for count := uint64(0); ; count++ {
		if _, err := io.ReadFull(upstream, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		size := binary.BigEndian.Uint32(header[:])
		total += uint64(size)
		if size > method.spec.MaxResponse || count >= uint64(method.spec.MaxItems) || total > uint64(method.spec.MaxTotal) {
			return errors.New("stream exceeds method limits")
		}
		if uint32(cap(item)) < size {
			item = make([]byte, size)
		}
		item = item[:size]
		if _, err := io.ReadFull(upstream, item); err != nil {
			return err
		}
		if _, err := io.Copy(output, bytes.NewReader(header[:])); err != nil {
			return err
		}
		if _, err := io.Copy(output, bytes.NewReader(item)); err != nil {
			return err
		}
	}
}
