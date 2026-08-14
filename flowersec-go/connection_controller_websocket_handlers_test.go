package flowersec

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

const (
	controllerClientRPC          uint32 = 901
	controllerClientNotification uint32 = 902
	controllerPendingServerRPC   uint32 = 903
)

func TestConnectionControllerWebSocketHandlersSurviveTwoGenerations(t *testing.T) {
	source := &webSocketHandlerRestartSource{}
	var rpcCalls atomic.Int32
	var notifications atomic.Int32
	handlers := NewRPCHandlers()
	if err := handlers.HandleRPC(controllerClientRPC, func(_ context.Context, request json.RawMessage) (any, *RPCError) {
		var payload map[string]any
		if err := json.Unmarshal(request, &payload); err != nil {
			return nil, &RPCError{Code: 400, Message: "invalid request"}
		}
		return map[string]any{"generation": rpcCalls.Add(1), "request": payload}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleNotification(controllerClientNotification, func(context.Context, json.RawMessage) error {
		notifications.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	controller, err := NewConnectionController(source, ConnectionControllerOptions{Connector: ConnectorOptions{
		Origin: "https://client.example", ConnectTimeout: 5 * time.Second, RPCHandlers: handlers,
	}})
	if err != nil {
		t.Fatal(err)
	}
	controller.Start(context.Background())
	t.Cleanup(func() {
		closeController(t, controller)
		source.stopAll()
	})

	firstClient := waitWebSocketControllerSession(t, controller, nil, 5*time.Second)
	firstGeneration := source.takeGeneration(t, 0)
	firstServer := firstGeneration.waitSession(t)
	var firstResponse struct {
		Generation int32          `json:"generation"`
		Request    map[string]any `json:"request"`
	}
	if err := firstServer.RPC().Call(context.Background(), controllerClientRPC, map[string]string{"phase": "first"}, &firstResponse); err != nil {
		t.Fatalf("first peer RPC: %v", err)
	}
	if firstResponse.Generation != 1 || firstResponse.Request["phase"] != "first" {
		t.Fatalf("first peer RPC response = %#v", firstResponse)
	}
	if err := firstServer.RPC().Notify(context.Background(), controllerClientNotification, map[string]string{"phase": "first"}); err != nil {
		t.Fatalf("first peer notification: %v", err)
	}
	waitAtomicCount(t, &notifications, 1)

	pendingDone := make(chan error, 1)
	go func() {
		var response any
		pendingDone <- firstClient.RPC().Call(context.Background(), controllerPendingServerRPC, nil, &response)
	}()
	select {
	case <-firstGeneration.pendingStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first generation pending RPC did not reach server handler")
	}
	_ = firstServer.Close()
	select {
	case err := <-pendingDone:
		if err == nil {
			t.Fatal("old pending RPC unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old pending RPC did not terminate with its Session")
	}

	secondClient := waitWebSocketControllerSession(t, controller, firstClient, 5*time.Second)
	if secondClient == firstClient {
		t.Fatal("controller reused the first Session object")
	}
	secondGeneration := source.takeGeneration(t, 1)
	secondServer := secondGeneration.waitSession(t)
	var secondResponse struct {
		Generation int32          `json:"generation"`
		Request    map[string]any `json:"request"`
	}
	if err := secondServer.RPC().Call(context.Background(), controllerClientRPC, map[string]string{"phase": "second"}, &secondResponse); err != nil {
		t.Fatalf("second peer RPC: %v", err)
	}
	if secondResponse.Generation != 2 || secondResponse.Request["phase"] != "second" {
		t.Fatalf("second peer RPC response = %#v", secondResponse)
	}
	if err := secondServer.RPC().Notify(context.Background(), controllerClientNotification, map[string]string{"phase": "second"}); err != nil {
		t.Fatalf("second peer notification: %v", err)
	}
	waitAtomicCount(t, &notifications, 2)
	if got := source.acquireCount(); got != 2 {
		t.Fatalf("artifact acquisitions = %d, want 2", got)
	}
	close(firstGeneration.pendingRelease)
	if err := controller.Close(context.Background()); err != nil {
		t.Fatalf("close controller: %v", err)
	}
	_ = secondServer.Close()
}

type webSocketHandlerGeneration struct {
	server         *httptest.Server
	session        chan Session
	pendingStarted chan struct{}
	pendingRelease chan struct{}
}

func (generation *webSocketHandlerGeneration) waitSession(t *testing.T) Session {
	t.Helper()
	select {
	case current := <-generation.session:
		return current
	case <-time.After(5 * time.Second):
		t.Fatal("accepted WebSocket Session was not published")
		return nil
	}
}

type webSocketHandlerRestartSource struct {
	mu          sync.Mutex
	generations []*webSocketHandlerGeneration
}

func (source *webSocketHandlerRestartSource) Acquire(ctx context.Context) (ArtifactLease, *ArtifactSourceError) {
	if err := ctx.Err(); err != nil {
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	generation := &webSocketHandlerGeneration{
		session: make(chan Session, 1), pendingStarted: make(chan struct{}), pendingRelease: make(chan struct{}),
	}
	var record controlplane.AuthorizationRecord
	serverHandlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	if err := serverHandlers.HandleRPC(controllerPendingServerRPC, func(ctx context.Context, _ json.RawMessage) (any, *RPCError) {
		close(generation.pendingStarted)
		select {
		case <-generation.pendingRelease:
			return map[string]bool{"late": true}, nil
		case <-ctx.Done():
			return nil, &RPCError{Code: 500, Message: "session ended"}
		}
	}); err != nil {
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	acceptor, err := NewAcceptor(AcceptorOptions{
		AllowedOrigins: []string{"https://client.example"}, MaxInboundStreams: 8,
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "controller-handler-lease")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*SessionHandlers, error) {
			return serverHandlers, nil
		},
		OnSession: func(sessionCtx context.Context, current Session, _ string) error {
			generation.session <- current
			<-sessionCtx.Done()
			return context.Cause(sessionCtx)
		},
	})
	if err != nil {
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	generation.server = httptest.NewServer(acceptor.Handler())
	endpoint := "ws" + strings.TrimPrefix(generation.server.URL, "http") + WebSocketDirectPath
	endpoints, err := controlplane.NewEndpointSet(endpoint)
	if err != nil {
		generation.server.Close()
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID: "go-controller-handlers", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 8,
		},
		Endpoints: endpoints, RendezvousGroupID: "go-controller-handlers-group",
		ListenerAudience: "go-controller-handlers-listener", UpstreamAddress: "127.0.0.1:23998",
	})
	if err != nil {
		generation.server.Close()
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	record = issued.AuthorizationRecord()
	artifact, err := ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		generation.server.Close()
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		generation.server.Close()
		return ArtifactLease{}, NewTerminalArtifactSourceError(err)
	}
	source.mu.Lock()
	source.generations = append(source.generations, generation)
	source.mu.Unlock()
	return lease, nil
}

func (source *webSocketHandlerRestartSource) takeGeneration(t *testing.T, index int) *webSocketHandlerGeneration {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		source.mu.Lock()
		if len(source.generations) > index {
			generation := source.generations[index]
			source.mu.Unlock()
			return generation
		}
		source.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("WebSocket generation %d was not created", index)
	return nil
}

func (source *webSocketHandlerRestartSource) acquireCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return len(source.generations)
}

func (source *webSocketHandlerRestartSource) stopAll() {
	source.mu.Lock()
	generations := append([]*webSocketHandlerGeneration(nil), source.generations...)
	source.mu.Unlock()
	for _, generation := range generations {
		generation.server.Close()
	}
}

func waitAtomicCount(t *testing.T, counter *atomic.Int32, expected int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for counter.Load() != expected && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := counter.Load(); got != expected {
		t.Fatalf("handler invocation count = %d, want %d", got, expected)
	}
}

func waitWebSocketControllerSession(t *testing.T, controller *ConnectionController, previous Session, timeout time.Duration) Session {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := controller.Snapshot()
		if snapshot.State == ConnectionConnected && snapshot.CurrentSession != nil && snapshot.CurrentSession != previous {
			return snapshot.CurrentSession
		}
		time.Sleep(5 * time.Millisecond)
	}
	snapshot := controller.Snapshot()
	t.Fatalf("controller did not publish WebSocket Session: %s failure=%v", snapshot, snapshot.Failure)
	return nil
}
