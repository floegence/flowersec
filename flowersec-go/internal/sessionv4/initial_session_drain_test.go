package sessionv4

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestInitialCoreDrainPreservesExistingDuplexAndUnreadFIN(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, framing := range []string{"stream", "messages"} {
			t.Run(profile+"/"+framing, func(t *testing.T) {
				var fixtures [2]initialCoreFixture
				pair, configs := initialTestPairPrepared(t, profile, framing, 4, initialCorePrepareCarrier(t, &fixtures, framing == "messages"))
				initial := startInitialCorePair(pair, configs, &fixtures)
				var cores [2]*SessionCore
				for role := range 2 {
					outcome := waitInitialCoreOutcome(t, initial[role])
					if outcome.err != nil {
						t.Fatal(outcome.err)
					}
					cores[role] = outcome.core
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				runs := make(chan error, 2)
				for _, core := range cores {
					go func() { runs <- core.Runtime().Run(ctx) }()
				}
				client, server := cores[0].Admission(), cores[1].Admission()
				h, result, err := client.OpenLocal(ctx, BusinessStream, "example/raw", nil, &CarrierAssociation{shared: client.sharedIngress}, fixtures[0].streamReservation(t, cores[0]), streamTestDeadline(t, cores[0].Engine()))
				if err != nil || !result.Complete {
					t.Fatal(result, err)
				}
				peer := OpenHandle{server, h.scope}
				waitCoreOpen(t, server, peer, true)
				if _, err := server.Decide(ctx, peer, BusinessStream, "", fixtures[1].streamReservation(t, cores[1]), server.termination.writer); err != nil {
					t.Fatal(err)
				}
				waitCoreOpen(t, client, h, false)
				left, err := client.Flow(h)
				if err != nil {
					t.Fatal(err)
				}
				right, err := server.Flow(peer)
				if err != nil {
					t.Fatal(err)
				}
				op, err := cores[0].Drain(0, 0)
				if err != nil {
					t.Fatal(err)
				}
				for {
					server.mu.Lock()
					received := server.peerGoAway.set
					server.mu.Unlock()
					if received {
						break
					}
					if ctx.Err() != nil {
						t.Fatal("peer did not receive GOAWAY")
					}
					runtime.Gosched()
				}
				for _, d := range []struct {
					source, target *StreamFlow
					data           string
				}{{left, right, "client during drain"}, {right, left, "server during drain"}} {
					if _, err := d.source.send.queueOwner.Write(ctx, []byte(d.data)); err != nil {
						t.Fatal(err)
					}
					var dst [32]byte
					read, err := d.target.receive.ReadInto(ctx, dst[:len(d.data)])
					if err != nil || string(dst[:read.Progress.Filled]) != d.data {
						t.Fatal(read, err)
					}
				}
				if _, err := right.send.queueOwner.Write(ctx, []byte("final")); err != nil {
					t.Fatal(err)
				}
				if err := right.send.queueOwner.CloseWrite(ctx); err != nil {
					t.Fatal(err)
				}
				if err := left.send.queueOwner.CloseWrite(ctx); err != nil {
					t.Fatal(err)
				}
				if err := right.send.queueOwner.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				if err := left.send.queueOwner.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				// Authenticated bidirectional FIN/DRAINED does not consume the
				// application's unread response or end its original read right.
				if result := op.Result(); result.Outcome != DrainPending {
					t.Fatal("unread FIN ended drain", result)
				}
				var dst [8]byte
				read, err := left.receive.ReadInto(ctx, dst[:])
				if err != nil || string(dst[:read.Progress.Filled]) != "final" || read.ReadTerminal != protocolv4.V4ReadTerminalEof {
					t.Fatal(read, err)
				}
				outcome, err := op.Wait(ctx)
				if err != nil || outcome.Outcome != Drained {
					t.Fatal(outcome, err)
				}
				again, err := cores[0].Drain(1, 1)
				if err != nil || again != op {
					t.Fatal("repeat lost original operation", err)
				}
				for range 2 {
					_ = waitRuntime(t, runs)
				}
				for role, core := range cores {
					core.Close()
					if err := core.WaitCleanup(ctx); err != nil {
						t.Fatal(role, err)
					}
					if err := core.Retire(); err != nil {
						t.Fatal(role, err)
					}
					if got := fixtures[role].root.Snapshot().Reservations; got != 1 {
						t.Fatal("retained core resources", role, got)
					}
				}
			})
		}
	}
}
