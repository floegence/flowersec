package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

const bridgeToken = "private-loopback-integration-token"

type peerEndpoint struct {
	ArtifactJSON string `json:"artifact_json"`
	BridgeToken  string `json:"bridge_token"`
	Origin       string `json:"origin"`
}

func main() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	defer listener.Close()

	origin := "http://" + listener.Addr().String()
	issued, err := controlplane.NewIssuer().IssuePrivateLoopbackDirect(controlplane.PrivateLoopbackIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "private-loopback-integration", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoint:          "ws://" + listener.Addr().String() + flowersec.WebSocketDirectPath,
		RendezvousGroupID: "private-loopback-integration",
		ListenerAudience:  "integration",
		UpstreamAddress:   listener.Addr().String(),
	})
	must(err)

	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
	must(err)
	must(handlers.HandleRPC(7001, func(context.Context, json.RawMessage) (any, *flowersec.RPCError) {
		return map[string]string{"server": "private-loopback"}, nil
	}))

	var bridgeAuthorizations atomic.Int32
	var runtimeAuthorizations atomic.Int32
	var releases atomic.Int32
	released := make(chan struct{}, 1)
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			runtimeAuthorizations.Add(1)
			return controlplane.AuthorizeRuntime(request, issued.AuthorizationRecord(), "private-loopback-lease")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		Release: func(context.Context, string) {
			if releases.Add(1) == 1 {
				released <- struct{}{}
			}
		},
		OnSession: func(ctx context.Context, session flowersec.Session, channelID string) error {
			if channelID != "private-loopback-integration" {
				return fmt.Errorf("unexpected channel %q", channelID)
			}
			_, waitErr := session.WaitTermination(ctx)
			if errors.Is(waitErr, context.Canceled) {
				return nil
			}
			return waitErr
		},
	})
	must(err)
	handler, err := acceptor.PrivateLoopbackHandler(flowersec.PrivateLoopbackHandlerOptions{
		AuthorizeRequest: func(request *http.Request) bool {
			bridgeAuthorizations.Add(1)
			return request.Header.Get("X-Flowersec-Private-Bridge-Token") == bridgeToken
		},
	})
	must(err)

	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	must(json.NewEncoder(os.Stdout).Encode(peerEndpoint{
		ArtifactJSON: string(issued.ArtifactJSON()),
		BridgeToken:  bridgeToken,
		Origin:       origin,
	}))

	select {
	case <-released:
	case err := <-serveErrors:
		must(err)
	case <-time.After(30 * time.Second):
		must(errors.New("private loopback session was not released"))
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	must(server.Shutdown(shutdownContext))
	if bridgeAuthorizations.Load() != 1 || runtimeAuthorizations.Load() != 1 || releases.Load() != 1 {
		must(fmt.Errorf("callback counts bridge/runtime/release = %d/%d/%d", bridgeAuthorizations.Load(), runtimeAuthorizations.Load(), releases.Load()))
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
