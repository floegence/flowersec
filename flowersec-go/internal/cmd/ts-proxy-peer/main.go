package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

type endpoint struct {
	Runtime      string `json:"runtime"`
	ArtifactJSON string `json:"artifact_json"`
	Origin       string `json:"origin"`
}

func main() {
	upstream := flag.String("upstream", "", "fixed loopback HTTP upstream origin")
	flag.Parse()
	if *upstream == "" {
		fail(errors.New("--upstream is required"))
	}

	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{MaxConcurrentStreams: 4})
	fail(err)
	proxy, err := flowersec.NewProxyServer(flowersec.ProxyServerOptions{
		Upstream:                    *upstream,
		UpstreamOrigin:              *upstream,
		AllowedOrigins:              []string{"https://app.example"},
		MaxConcurrentStreams:        4,
		MaxJSONFrameBytes:           4096,
		MaxChunkBytes:               8,
		MaxBodyBytes:                8,
		MaxWebSocketFrameBytes:      32,
		DefaultHTTPRequestTimeout:   time.Second,
		MaxHTTPRequestTimeout:       time.Second,
		ExtraRequestHeaders:         []string{"cookie", "origin", "x-request-id"},
		ExtraResponseHeaders:        []string{"x-visible"},
		BlockedResponseHeaders:      []string{"location"},
		ExtraWebSocketHeaders:       []string{"x-request-id"},
		ForbiddenCookieNames:        []string{"secret"},
		ForbiddenCookieNamePrefixes: []string{"private_"},
		OnError: func(err error) {
			// Keep peer diagnostics on stderr; the endpoint JSON remains machine-readable.
			fmt.Fprintf(os.Stderr, "proxy handler error: %v\n", err)
		},
	})
	fail(err)
	defer proxy.Close()
	fail(proxy.Register(handlers))

	var record controlplane.AuthorizationRecord
	released := make(chan struct{}, 1)
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins:    []string{"https://app.example"},
		MaxInboundStreams: 8,
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "proxy-matrix-go")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		Release: func(context.Context, string) {
			select {
			case released <- struct{}{}:
			default:
			}
		},
		OnSession: func(ctx context.Context, session flowersec.Session, _ string) error {
			_, err := session.WaitTermination(ctx)
			return err
		},
	})
	fail(err)
	server := httptest.NewServer(acceptor.Handler())
	defer server.Close()

	endpoints, err := controlplane.NewEndpointSet("ws" + strings.TrimPrefix(server.URL, "http") + flowersec.WebSocketDirectPath)
	fail(err)
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID:         "browser-proxy-go",
			ExpiresAt:         time.Now().Add(time.Minute),
			MaxInboundStreams: 8,
		},
		Endpoints:         endpoints,
		RendezvousGroupID: "browser-proxy-go",
		ListenerAudience:  "browser-proxy-matrix",
		UpstreamAddress:   server.Listener.Addr().String(),
	})
	fail(err)
	record = issued.AuthorizationRecord()
	fail(json.NewEncoder(os.Stdout).Encode(endpoint{
		Runtime: "go", ArtifactJSON: string(issued.ArtifactJSON()), Origin: "https://app.example",
	}))

	select {
	case <-released:
	case <-time.After(20 * time.Second):
		fail(errors.New("proxy matrix session did not release"))
	}
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
