package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

// This peer publishes two independent HTTP sessions on one application port.
func main() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	var records sync.Map
	var issuedCount, authorized, releases atomic.Int32
	released := make(chan struct{}, 2)
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
	must(err)
	must(handlers.HandleRPC(7001, func(context.Context, json.RawMessage) (any, *flowersec.RPCError) {
		return map[string]string{"server": "http-direct"}, nil
	}))
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			record, ok := records.LoadAndDelete(request.LookupKey())
			if !ok {
				return controlplane.AuthorizationResponse{}, errors.New("unknown or spent authorization")
			}
			id := authorized.Add(1)
			return controlplane.AuthorizeRuntime(request, record.(controlplane.AuthorizationRecord), fmt.Sprintf("http-lease-%d", id))
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		Release: func(context.Context, string) { releases.Add(1); released <- struct{}{} },
		OnSession: func(ctx context.Context, current flowersec.Session, _ string) error {
			_, err := current.WaitTermination(ctx)
			return err
		},
	})
	must(err)
	transport, err := acceptor.HTTPDirectHandler(flowersec.HTTPDirectHandlerOptions{AuthorizeRequest: func(r *http.Request) bool { return r.Host == listener.Addr().String() }})
	must(err)
	app := http.NewServeMux()
	app.HandleFunc("/artifact", func(w http.ResponseWriter, r *http.Request) {
		id := issuedCount.Add(1)
		issued, err := controlplane.NewIssuer().IssueHTTPDirect(controlplane.HTTPDirectIssueOptions{
			Session:           controlplane.SessionOptions{ChannelID: fmt.Sprintf("http-client-%d", id), ExpiresAt: time.Now().Add(time.Minute)},
			Endpoint:          "ws://" + listener.Addr().String() + flowersec.WebSocketDirectPath,
			RendezvousGroupID: fmt.Sprintf("http-group-%d", id), ListenerAudience: "http-integration", UpstreamAddress: listener.Addr().String(),
		})
		if err != nil {
			http.Error(w, "issue failed", 500)
			return
		}
		records.Store(issued.LookupKey(), issued.AuthorizationRecord())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(issued.ArtifactJSON())
	})
	app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("application")) })
	server, err := flowersec.NewHTTPDirectServer(flowersec.HTTPDirectServerOptions{Handler: transport, ApplicationHandler: app, ReadHeaderTimeout: 5 * time.Second})
	must(err)
	errorsCh := make(chan error, 1)
	go func() { errorsCh <- server.Serve(listener) }()
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{"origin": origin}))
	for range 2 {
		select {
		case <-released:
		case err := <-errorsCh:
			must(err)
		case <-time.After(30 * time.Second):
			must(errors.New("sessions did not finish"))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	must(server.Shutdown(ctx))
	if authorized.Load() != 2 || releases.Load() != 2 {
		must(errors.New("independent session accounting failed"))
	}
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
