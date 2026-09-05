package sessionv3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpc"
)

type sessionRPCPeer struct {
	session *engineSession

	permit chan struct{}
	client *rpc.Client
}

func (peer *sessionRPCPeer) Call(ctx context.Context, typeID uint32, request, response any) error {
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
		return errors.New("Flowersec v3 RPC response payload is empty")
	}
	return json.Unmarshal(responsePayload, response)
}

func (peer *sessionRPCPeer) Notify(ctx context.Context, typeID uint32, request any) error {
	if ctx == nil {
		ctx = context.Background()
	}
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
	client := rpc.NewClient(stream)
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
		err = server.Serve(s.ctx)
	}
	if s.ctx.Err() == nil {
		s.fail(fmt.Errorf("Flowersec v3 RPC stream failed: %w", err))
	}
}

var _ RPCPeer = (*sessionRPCPeer)(nil)
