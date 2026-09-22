package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func factoryStreamConfig() SessionStreamConfig {
	return SessionStreamConfig{ReceivePoolBytes: 128, ReceiveBytes: 64, InitialReceiveLimit: 64,
		SendBytes: 64, QueueBytes: 64, WriteWaiters: 2, MaxPlaintext: 128, Chunk: 64, RuntimeBytes: 16384}
}

func factoryCorePair(t *testing.T, framing string, stream SessionStreamConfig) ([2]*SessionCore, *[2]initialCoreFixture, context.Context) {
	t.Helper()
	var fixtures [2]initialCoreFixture
	pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, framing, 4,
		initialCorePrepareConfig(t, &fixtures, framing == "messages", func(c *SessionCoreConfig) { c.Streams = stream }))
	results := startInitialCorePair(pair, configs, &fixtures)
	var cores [2]*SessionCore
	for role := range 2 {
		result := waitInitialCoreOutcome(t, results[role])
		if result.err != nil {
			t.Fatal(result.err)
		}
		cores[role] = result.core
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ended := make(chan error, 2)
	for role := range 2 {
		go func() { ended <- cores[role].Runtime().Run(ctx) }()
	}
	t.Cleanup(func() {
		for _, core := range cores {
			core.Close()
		}
		for range 2 {
			_ = waitRuntime(t, ended)
		}
		retireInitialCorePair(t, pair, &fixtures)
		cancel()
	})
	return cores, &fixtures, ctx
}

type factoryStreamResult struct {
	stream *StreamOwnership
	err    error
}

func factoryOpenPair(t *testing.T, cores [2]*SessionCore, ctx context.Context) [2]*StreamOwnership {
	t.Helper()
	done := make(chan factoryStreamResult, 1)
	go func() {
		stream, err := cores[0].OpenStream(ctx, "example/raw", []byte("factory"), streamTestDeadline(t, cores[0].Engine()))
		done <- factoryStreamResult{stream, err}
	}()
	h, err := cores[1].Admission().NextPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := cores[1].AcceptStream(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	local := <-done
	if local.err != nil {
		t.Fatal(local.err)
	}
	streams := [2]*StreamOwnership{local.stream, peer}
	t.Cleanup(func() {
		for _, stream := range streams {
			_ = stream.Cancel()
			if err := stream.Release(); err != nil {
				t.Error(err)
			}
		}
	})
	return streams
}

func TestSessionStreamFactoryTransfersAcceptedDuplexOwners(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		t.Run(framing, func(t *testing.T) {
			cores, _, ctx := factoryCorePair(t, framing, factoryStreamConfig())
			streams := factoryOpenPair(t, cores, ctx)
			for source := range 2 {
				body := []byte("owned duplex bytes")
				if n, err := streams[source].WriteAll(ctx, body); n != len(body) || err != nil {
					t.Fatal(n, err)
				}
				var dst [32]byte
				read, err := streams[1-source].ReadInto(ctx, dst[:])
				if err != nil || string(dst[:read.Progress.Filled]) != string(body) {
					t.Fatal(read, err)
				}
			}
			for role, stream := range streams {
				if stream.flow.receive.pool != cores[role].plan.receivePool {
					t.Fatal("factory escaped the original Session receive pool")
				}
			}
		})
	}
}

func TestSessionStreamFactorySharesSignedCreditAcrossStreams(t *testing.T) {
	config := factoryStreamConfig()
	config.ReceivePoolBytes, config.ReceiveBytes, config.InitialReceiveLimit = 131072, 65536, 40000
	cores, fixtures, ctx := factoryCorePair(t, "stream", config)
	_ = factoryOpenPair(t, cores, ctx)
	before := fixtures[0].root.Snapshot()
	stream, err := cores[0].OpenStream(ctx, "example/second", nil, streamTestDeadline(t, cores[0].Engine()))
	if stream != nil || !errors.Is(err, ErrCredit) {
		t.Fatal("a second Stream multiplied the signed Session credit", err)
	}
	if after := fixtures[0].root.Snapshot(); after != before {
		t.Fatal("failed OPEN retained private resource charges", before, after)
	}
	if got := cores[0].plan.receivePool.Outstanding(); got != 40000 {
		t.Fatal("failed OPEN changed the original receive promises", got)
	}
}

func TestSessionStreamFactoryCanceledAcceptanceDoesNotReopen(t *testing.T) {
	cores, _, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	opening, cancel := context.WithCancel(ctx)
	done := make(chan factoryStreamResult, 1)
	go func() {
		stream, err := cores[0].OpenStream(opening, "example/raw", nil, streamTestDeadline(t, cores[0].Engine()))
		done <- factoryStreamResult{stream, err}
	}()
	h, err := cores[1].Admission().NextPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	result := <-done
	if result.stream != nil || !errors.Is(result.err, context.Canceled) {
		t.Fatal(result.err)
	}
	peer, err := cores[1].AcceptStream(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.Cancel()
		if err := peer.Release(); err != nil {
			t.Error(err)
		}
	})
	local := OpenHandle{owner: cores[0].Admission(), scope: h.Scope()}
	if err := cores[0].Admission().WaitOutcome(ctx, local); !errors.Is(err, ErrAbandoned) {
		t.Fatal("late peer acceptance revived canceled factory output", err)
	}
}

func TestSessionStreamFactoryGeometryRejectedBeforeCoreReservation(t *testing.T) {
	for _, change := range []func(*SessionStreamConfig){
		func(c *SessionStreamConfig) { c.InitialReceiveLimit = c.ReceiveBytes + 1 },
		func(c *SessionStreamConfig) { c.Chunk = int(c.SendBytes) + 1 },
		func(c *SessionStreamConfig) { c.MaxPlaintext = 64 },
		func(c *SessionStreamConfig) { c.RuntimeBytes = 0 },
	} {
		c := corePlanUnitConfig(t, false)
		c.Streams = factoryStreamConfig()
		root, environment, owner, scope := corePlanUnitRoot(t, c, -1, false)
		before := root.Snapshot()
		change(&c.Streams)
		if p, err := NewSessionCorePlan(c, root, owner, environment, scope); p != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("invalid factory geometry admitted", err)
		}
		if root.Snapshot() != before {
			t.Fatal("invalid geometry changed root")
		}
	}
}
