package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

type endpoint struct {
	Runtime      string `json:"runtime"`
	ArtifactJSON string `json:"artifact_json"`
	Origin       string `json:"origin"`
	TrustPEM     string `json:"trust_pem"`
}

func main() { fail(runCurrentProxyPeer()) }

func runCurrentProxyPeer() (err error) {
	upstream := flag.String("upstream", "", "fixed loopback HTTP upstream origin")
	origin := flag.String("origin", "https://app.example", "exact browser and proxy external origin")
	maxBodyBytes := flag.Int64("max-body-bytes", 8, "maximum proxied HTTP body size")
	httpTimeout := flag.Duration("http-timeout", time.Second, "proxy HTTP request timeout")
	flag.Parse()
	if *upstream == "" || *maxBodyBytes < 1 || *httpTimeout <= 0 {
		return errors.New("invalid proxy peer options")
	}
	parsed, err := url.Parse(*origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.String() != parsed.Scheme+"://"+parsed.Host {
		return errors.New("--origin must be an exact origin")
	}
	reporter, err := interopharness.NewPeerReporter()
	if err != nil {
		return err
	}
	reporter.ApplicationProfile = "services"
	defer func() { err = errors.Join(err, reporter.Close()) }()
	proxy, err := flowersec.NewProxyServer(flowersec.ProxyServerOptions{Upstream: *upstream, UpstreamOrigin: *upstream, AllowedOrigins: []string{*origin}, MaxConcurrentStreams: 4, MaxMetadataBytes: 4096, MaxChunkBytes: 8, MaxBodyBytes: *maxBodyBytes, MaxWebSocketFrameBytes: 32,
		DefaultHTTPRequestTimeout: *httpTimeout, MaxHTTPRequestTimeout: *httpTimeout, ExtraRequestHeaders: []string{"cookie", "origin", "x-request-id"}, ExtraResponseHeaders: []string{"x-visible"}, BlockedResponseHeaders: []string{"location"}, ExtraWebSocketHeaders: []string{"x-request-id"}, ForbiddenCookieNames: []string{"secret"}, ForbiddenCookieNamePrefixes: []string{"private_"}, OnError: func(err error) { fmt.Fprintf(os.Stderr, "proxy handler error: %v\n", err) }})
	if err != nil {
		return err
	}
	reporter.Cleanup(func() { reporter.ErrorIf(proxy.Close()) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server, err := interopharness.NewServer(ctx, reporter, interopharness.ServerOptions{Carrier: "websocket", Origin: *origin, Handlers: func(runtime *interopharness.Runtime, role uint8) (flowersec.StreamHandlerPlanConfig, error) {
		interopharness.ConfigureRPC(runtime, role, "flowersec.proxy-test", []interopharness.RPCMethod{{Type: 7001, Handle: func(context.Context, []byte) ([]byte, error) { return []byte(`{"server":"proxy"}`), nil }}})
		config := flowersec.StreamHandlerPlanConfig{RuntimeBytes: 16384}
		err := proxy.RegisterStreamHandlers(&config, func(_ context.Context, binding any, _ []byte) error {
			if binding != role {
				return errors.New("proxy application lease mismatch")
			}
			return nil
		})
		return config, err
	}})
	if err != nil {
		return err
	}
	material := server.Material()
	artifactJSON, err := material.JSON()
	if err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"runtime": "go", "artifact_json": artifactJSON, "origin": *origin, "trust_pem": server.TrustPEM, "wire_revision": 4, "profile": material.Profile, "source": material.Source}); err != nil {
		return err
	}
	session, err := server.WaitSession(ctx)
	if err != nil {
		return err
	}
	if err = session.WaitTermination(ctx); err != nil {
		var terminal *flowersec.SessionError
		// The client validates application behavior before explicitly closing
		// its Session. That abort retires the carrier without a peer Drain
		// receipt; this side still requires real cleanup and lease release.
		if ctx.Err() != nil || !errors.As(err, &terminal) ||
			(terminal.Code() != flowersec.SessionClosed && terminal.Code() != flowersec.SessionOperationFailed) {
			return err
		}
	}
	if err = session.WaitCleanup(ctx); err != nil {
		return err
	}
	if server.Runtime.Authorized[1].Load() != 1 || server.Runtime.Released[1].Load() != 1 {
		return errors.New("proxy Session application lease did not release exactly once")
	}
	return nil
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
