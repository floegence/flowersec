package sessionv3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/rpc"
)

type sessionRPCPeer struct {
	session *engineSession

	permit chan struct{}
	client *rpc.Client
	active int // guarded by session.openMu to order admission with close
}

// Charge before opening the stream or marshaling: a waiting writer can own a
// complete encoded message even though its first byte has not reached the wire.
func (peer *sessionRPCPeer) beginSend(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	peer.session.openMu.Lock()
	defer peer.session.openMu.Unlock()
	if peer.session.lifecycle >= lifecycleClosing || peer.session.ctx.Err() != nil {
		return peer.session.sessionError()
	}
	limit := peer.session.config.RPCServerOptions.MaxConcurrentRequests
	if limit == 0 {
		limit = defaults.RPCMaxConcurrentRequests
	}
	if peer.active >= limit {
		return ErrResourceExhausted
	}
	peer.active++
	peer.session.wg.Add(1)
	return nil
}

func (peer *sessionRPCPeer) endSend() {
	peer.session.openMu.Lock()
	peer.active--
	peer.session.openMu.Unlock()
	peer.session.wg.Done()
}

func (peer *sessionRPCPeer) Call(ctx context.Context, typeID uint32, request, response any) error {
	if err := peer.beginSend(ctx); err != nil {
		return err
	}
	defer peer.endSend()
	client, err := peer.clientFor(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	responsePayload, responseError, err := client.Call(ctx, typeID, payload)
	if err != nil {
		return err
	}
	if responseError != nil {
		return rpc.NewCallError(typeID, responseError)
	}
	if response == nil {
		return nil
	}
	if len(responsePayload) == 0 {
		return errors.New("flowersec v5 RPC response payload is empty")
	}
	return json.Unmarshal(responsePayload, response)
}

func (peer *sessionRPCPeer) Notify(ctx context.Context, typeID uint32, request any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := peer.beginSend(ctx); err != nil {
		return err
	}
	defer peer.endSend()
	client, err := peer.clientFor(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return client.NotifyContext(ctx, typeID, payload)
}

func (peer *sessionRPCPeer) OnNotify(typeID uint32, handler func(context.Context, []byte)) func() {
	if handler == nil {
		return func() {}
	}
	if peer.session.ctx.Err() != nil {
		return func() {}
	}
	return peer.session.config.RPCRouter.OnNotify(typeID, func(ctx context.Context, payload json.RawMessage) {
		handler(ctx, payload)
	})
}

func (peer *sessionRPCPeer) clientFor(ctx context.Context) (*rpc.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case peer.permit <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-peer.session.ctx.Done():
		return nil, peer.session.sessionError()
	}
	defer func() { <-peer.permit }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if peer.client != nil {
		return peer.client, nil
	}
	stream, err := peer.session.openStream(ctx, reservedRPCStreamKind, Metadata{}, true)
	if err != nil {
		return nil, err
	}
	client, err := rpc.NewClientWithLimits(stream, peer.session.config.RPCServerOptions.FrameLimits)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	peer.client = client
	return client, nil
}

func (s *engineSession) serveRPCStream(stream *encryptedStream) {
	s.rpcServerMu.Lock()
	if s.rpcServing {
		s.rpcServerMu.Unlock()
		stream.localReset(ErrSessionProtocol)
		return
	}
	s.rpcServing = true
	s.rpcServerMu.Unlock()

	router := s.config.RPCRouter
	if router == nil {
		router = rpc.NewRouter()
	}
	server, err := rpc.NewServerWithOptions(stream, router, s.config.RPCServerOptions)
	if err == nil {
		err = server.Serve(context.WithValue(s.ctx, rpcChannelContextKey{}, s.config.ChannelID))
	}
	if s.ctx.Err() == nil {
		s.fail(fmt.Errorf("flowersec v5 RPC stream failed: %w", err))
	}
}

type rpcChannelContextKey struct{}

func RPCChannelID(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	id, ok := ctx.Value(rpcChannelContextKey{}).(string)
	return id, ok && id != ""
}

var _ RPCPeer = (*sessionRPCPeer)(nil)
