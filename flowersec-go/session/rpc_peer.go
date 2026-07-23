package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v2/rpc"
)

type sessionRPCPeer struct {
	session *engineSession

	mu     sync.Mutex
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
		return errors.New("Flowersec v2 RPC response payload is empty")
	}
	return json.Unmarshal(responsePayload, response)
}

func (peer *sessionRPCPeer) Notify(ctx context.Context, typeID uint32, request any) error {
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
	return client.Notify(typeID, payload)
}

func (peer *sessionRPCPeer) clientFor(ctx context.Context) (*rpc.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
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
		s.fail(fmt.Errorf("Flowersec v2 RPC stream failed: %w", err))
	}
}

var _ RPCPeer = (*sessionRPCPeer)(nil)
