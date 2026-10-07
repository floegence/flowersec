package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

func currentParitySessions(t *testing.T, carrier string, serverConfigure, clientConfigure interopharness.HandlerConfig) (context.Context, *fs.Session, *fs.Session, *interopharness.Reporter, *interopharness.Reporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	newReporter := func() *interopharness.Reporter {
		r, err := interopharness.NewPeerReporter()
		if err != nil {
			t.Fatal(err)
		}
		r.ApplicationProfile = "services"
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		return r
	}
	serverReporter, clientReporter := newReporter(), newReporter()
	server, err := interopharness.NewServer(ctx, serverReporter, interopharness.ServerOptions{Carrier: carrier, Handlers: serverConfigure})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := server.Material().JSON()
	if err != nil {
		t.Fatal(err)
	}
	client, err := interopharness.NewClient(ctx, clientReporter, wire, server.TrustPEM, server.Origin, clientConfigure)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.WaitSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, session, accepted, clientReporter, serverReporter
}

func TestCurrentParityClosesAfterApplicationTraffic(t *testing.T) {
	for _, carrier := range []string{"websocket", "raw-quic", "webtransport"} {
		t.Run(carrier, func(t *testing.T) {
			serverState, clientState := newCurrentParityState(), newCurrentParityState()
			ctx, session, accepted, clientReporter, serverReporter := currentParitySessions(t, carrier, serverState.configure, clientState.configure)
			results := make(chan error, 2)
			go func() {
				err := exerciseCurrentClient(ctx, session, carrier, clientState, clientReporter)
				if err != nil {
					err = fmt.Errorf("client: %w", err)
				}
				results <- err
			}()
			go func() {
				err := exerciseCurrentServer(ctx, accepted, carrier, serverState, serverReporter)
				if err != nil {
					err = fmt.Errorf("server: %w", err)
				}
				results <- err
			}()
			for range 2 {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestCurrentParityDrainPreservesAcceptedReply(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer closeIfOpen(release)
	var definitions [2]*interopharness.RPCDefinition
	configure := func(runtime *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
		definitions[role] = interopharness.ConfigureRPC(runtime, role, parityNamespace, []interopharness.RPCMethod{{Type: echoRPC, Handle: func(ctx context.Context, payload []byte) ([]byte, error) {
			if role == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return bytes.Clone(payload), nil
		}}})
		return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384}, nil
	}
	ctx, session, accepted, clientReporter, _ := currentParitySessions(t, "websocket", configure, configure)
	service, err := definitions[0].Bind(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	clientReporter.Cleanup(func() { service.Close(); clientReporter.ErrorIf(service.WaitCleanup(ctx)) })
	result := make(chan error, 1)
	go func() { result <- currentCall(ctx, service, echoRPC, "ping") }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("call did not enter the server handler: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := session.Drain(5000); err != nil {
		t.Fatal(err)
	}
	observer, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	progress, waitErr := session.WaitDrain(observer)
	cancel()
	if waitErr == nil || progress.Outcome != fs.DrainPending {
		t.Fatalf("accepted reply lost its original channel: %+v, %v", progress, waitErr)
	}
	select {
	case err := <-result:
		t.Fatalf("accepted call ended before handler release: %v", err)
	default:
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	progress, err = session.WaitDrain(ctx)
	if err != nil || progress.Outcome != fs.Drained {
		t.Fatalf("drain after original reply: %+v, %v", progress, err)
	}
	for _, original := range []*fs.Session{session, accepted} {
		_ = original.WaitTermination(ctx)
		if err := original.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func closeIfOpen(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}
