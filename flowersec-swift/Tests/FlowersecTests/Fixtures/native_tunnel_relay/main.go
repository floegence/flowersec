// This source runs only from the explicit Swift native regression fixture.
// Both relay hops, claims, pairing, ServerAllow and endpoint READY are owned by
// the production Go runtime. Stdout is a bounded fixture protocol, not a log.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

const echoKind = "swift.native.tunnel.echo"

func emit(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() (result error) {
	if len(os.Args) != 3 {
		return errors.New("original artifact directory and private client installation path are required")
	}
	signals, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signals, 45*time.Second)
	defer cancel()
	relayReporter, err := interopharness.NewReporter(os.Args[1])
	if err != nil {
		return err
	}
	relayReporter.RouteHost = "localhost"
	defer func() { result = errors.Join(result, relayReporter.Close()) }()
	relay, err := interopharness.NewPoolRelay(ctx, relayReporter, [2]string{"websocket", "websocket"}, "https://client.example")
	if err != nil {
		return fmt.Errorf("original pool relay: %w", err)
	}
	materials, err := relay.EndpointMaterialsJSON()
	if err != nil {
		return err
	}
	serverReporter, err := relayReporter.ForkAuthority()
	if err != nil {
		return err
	}
	serverReporter.ApplicationProfile = "services"
	defer func() { result = errors.Join(result, serverReporter.Close()) }()
	var echoes atomic.Int32
	configure := func(runtime *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
		interopharness.ConfigurePeerRPC(runtime, role, "swift-native-server")
		return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384, Handlers: []fs.RawStreamHandlerConfig{{Kind: echoKind, Slots: 1, WorkClass: fs.WorkResident,
			AuthorizeOpen: func(_ context.Context, binding any, _ []byte) error {
				if binding != role {
					return errors.New("original authenticated server lease is missing")
				}
				return nil
			},
			Handler: func(ctx context.Context, _ any, _ []byte, stream *fs.StreamOwnership) error {
				var input [32]byte
				filled := 0
				for {
					if filled == len(input) {
						return errors.New("native tunnel regression input exceeds its bound")
					}
					read, err := stream.ReadInto(ctx, input[filled:])
					filled += int(read.Progress.Filled)
					if errors.Is(err, io.EOF) || read.ReadTerminal == protocolv4.V4ReadTerminalEof {
						break
					}
					if err != nil {
						return err
					}
				}
				if string(input[:filled]) != "native-two-leg-ready" {
					return errors.New("native tunnel regression input changed")
				}
				if _, err := stream.WriteAll(ctx, []byte("original-relay-ready")); err != nil {
					return err
				}
				if err := stream.Finish(ctx); err != nil {
					return err
				}
				echoes.Add(1)
				return nil
			},
		}}}, nil
	}
	server, err := interopharness.NewTunnelServer(ctx, serverReporter, materials[1], relay.TrustPEM, relay.Origin, configure,
		interopharness.TunnelServerOptions{TLSCertificatePEM: relay.ServerTLSCertificatePEM, TLSPrivateKeyPEM: relay.ServerTLSPrivateKeyPEM})
	if err != nil {
		return fmt.Errorf("original tunnel server: %w", err)
	}
	installation, binding, err := server.LocalPoolClientConfiguration()
	if err != nil {
		return err
	}
	installed, err := json.Marshal(installation)
	if err != nil {
		return err
	}
	if err = os.WriteFile(os.Args[2], installed, 0600); err != nil {
		return err
	}
	clear(installed)
	defer os.Remove(os.Args[2])
	authority := relay.Runtime.Authority
	if err = emit(map[string]any{"type": "material", "material": json.RawMessage(materials[0]), "trust_pem": relay.TrustPEM,
		"tenant": authority.BrowserTenant, "audience": authority.BrowserAudience, "client_subject": authority.BrowserClientSubject, "server_subject": authority.BrowserServerSubject,
		"epoch_ms": relayReporter.AuthorityEpochMS(),
		"ready":    map[string]any{"type": "ready", "wire_revision": 4, "carrier": "websocket", "path": "tunnel", "artifact_json": materials[0], "trust_pem": relay.TrustPEM, "profile": authority.Admission[0].Initial.Profile, "source": "preauthorized_pool", "origin": relay.Origin, "server_allow": binding}}); err != nil {
		return err
	}
	commands := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, 1024)))
	var command struct {
		Type string `json:"type"`
	}
	if err = commands.Decode(&command); err != nil {
		return err
	}
	if command.Type != "start" {
		return errors.New("original native relay requires start")
	}
	relay.Start()
	if err = emit(map[string]any{"type": "relay-started"}); err != nil {
		return err
	}
	session, err := server.Accept(ctx)
	if err != nil {
		return err
	}
	if server.Client.Runtime.Authorized[1].Load() != 1 {
		return errors.New("original server READY lacks its application admission")
	}
	if err = emit(map[string]any{"type": "server-ready", "authorized": server.Client.Runtime.Authorized[1].Load()}); err != nil {
		return err
	}
	if err = commands.Decode(&command); err != nil {
		return err
	}
	if command.Type != "close" {
		return errors.New("original native relay requires close")
	}
	if echoes.Load() != 1 {
		return errors.New("original paired relay did not carry the end-to-end echo")
	}
	if err = session.Close(); err != nil {
		return err
	}
	cleanup, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCleanup()
	routeErr := relay.Host.Wait(cleanup)
	relay.Host.Close()
	relay.Native.Close()
	if err = relay.Host.WaitCleanup(cleanup); err != nil {
		return err
	}
	if err = relay.Native.WaitCleanup(cleanup); err != nil {
		return err
	}
	if routeErr != nil && !errors.Is(routeErr, context.Canceled) && !errors.Is(routeErr, io.EOF) && !errors.Is(routeErr, net.ErrClosed) && !errors.Is(routeErr, cryptov4.ErrClosed) && !errors.Is(routeErr, resourcev4.ErrClosed) && !errors.Is(routeErr, sessionv4.ErrPeerClosed) && !errors.Is(routeErr, native.ErrConnectionLost) {
		return routeErr
	}
	if err = serverReporter.Close(); err != nil {
		return err
	}
	if server.Client.Runtime.Released[1].Load() != 1 {
		return errors.New("original server lease or callback is still retained")
	}
	if err = relayReporter.Close(); err != nil {
		return err
	}
	return emit(map[string]any{"type": "complete", "echoes": echoes.Load(), "authorized": server.Client.Runtime.Authorized[1].Load(),
		"released": server.Client.Runtime.Released[1].Load(), "relay_cleanup": true})
}
