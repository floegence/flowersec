package rawquic

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestNativeAcceptWaitsForOriginalCapacity(t *testing.T) {
	for _, outcome := range []string{"release", "cancel", "close"} {
		t.Run(outcome, func(t *testing.T) {
			client, server := ownedTestPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			maintenance, err := client.OpenMaintenance(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retireTestStream(t, maintenance)
			if _, err := maintenance.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			peerMaintenance, err := server.AcceptMaintenance(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retireTestStream(t, peerMaintenance)
			var held [3]native.StreamProtection
			if err := client.ProtectNativeStreams(held[:]); err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, position := range held {
					position.Close()
				}
			}()
			type result struct {
				stream *OwnedStream
				err    error
			}
			accepted := make(chan result, 1)
			waitCtx, stopWait := context.WithCancel(ctx)
			defer stopWait()
			go func() { s, err := client.AcceptStream(waitCtx); accepted <- result{s, err} }()
			for {
				client.mu.Lock()
				waiting := client.accepting && client.calls == 1 && client.streamWake != nil
				client.mu.Unlock()
				if waiting {
					break
				}
				select {
				case result := <-accepted:
					t.Fatal("capacity terminated the acceptor", result.err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			// Exactly one acceptor may hold the original waiting position.
			if _, err := client.AcceptStream(ctx); !errors.Is(err, resourcev4.ErrCapacity) {
				t.Fatal("a second acceptor took ownership", err)
			}
			switch outcome {
			case "release":
				held[0].Close()
				peer, err := server.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				retireTestStream(t, peer)
				if _, err := peer.Write([]byte{7}); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				stopWait()
			case "close":
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case result := <-accepted:
				if outcome == "release" {
					if result.err != nil {
						t.Fatal("acceptor did not resume on original connection", result.err)
					}
					retireTestStream(t, result.stream)
					var body [1]byte
					if _, err := io.ReadFull(result.stream, body[:]); err != nil || body[0] != 7 {
						t.Fatal(body, err)
					}
				} else if outcome == "cancel" && !errors.Is(result.err, context.Canceled) || outcome == "close" && !errors.Is(result.err, resourcev4.ErrClosed) {
					t.Fatal("wrong terminal cause", result.err)
				}
			case <-ctx.Done():
				t.Fatal("acceptor retained its original call", ctx.Err())
			}
			client.mu.Lock()
			waiting, calls := client.accepting, client.calls
			client.mu.Unlock()
			if waiting || calls != 0 {
				t.Fatal("acceptor did not return its original responsibility")
			}
		})
	}
}

func TestNativeProtectionReservesActualProviderSlotsAndRetirement(t *testing.T) {
	client, _ := ownedTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	maintenance, err := client.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, maintenance)
	var protected [3]native.StreamProtection
	if err := client.ProtectNativeStreams(protected[:]); err != nil {
		t.Fatal(err)
	}
	for _, p := range protected {
		defer p.Close()
	}
	if _, err := client.OpenStream(ctx); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("ordinary create stole declared capacity", err)
	}
	var excess [1]native.StreamProtection
	if err := client.ProtectNativeStreams(excess[:]); !errors.Is(err, resourcev4.ErrCapacity) || excess[0] != nil {
		t.Fatal("partial declaration escaped exhaustion", err)
	}
	p := protected[0]
	first, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close(); _ = first.Retire() })
	if err := p.CheckAvailable(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("active provider slot reused", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckAvailable(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("Close was treated as actual retirement", err)
	}
	if err := first.Retire(); err != nil {
		t.Fatal(err)
	}
	second, err := p.Open(ctx)
	if err != nil {
		t.Fatal("retired slot did not return to its declaration", err)
	}
	t.Cleanup(func() { _ = second.Close(); _ = second.Retire() })
	if _, err := first.Write([]byte("stale")); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("stale stream reached its replacement", err)
	}
	p.Close()
	if _, err := client.OpenStream(ctx); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("closing declaration refunded live provider owner", err)
	}
	_ = second.Close()
	if err := second.Retire(); err != nil {
		t.Fatal(err)
	}
	ordinary, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal("closed, physically retired slot stayed protected", err)
	}
	retireTestStream(t, ordinary)
	if _, err := p.Open(ctx); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed declaration was resurrected", err)
	}
}
