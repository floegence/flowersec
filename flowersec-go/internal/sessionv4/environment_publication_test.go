package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestEnvironmentPublicationOwnsFirstHandlerWhileTransportProgresses(t *testing.T) {
	for _, outcome := range []string{"close_before_handoff", "publish", "guarantee_loss"} {
		publish := outcome == "publish"
		for _, framing := range []string{"stream", "messages"} {
			t.Run(outcome+"/"+framing, func(t *testing.T) {
				var host *EnvironmentSession
				provider := &changingAssuranceProvider{preparedTestProvider: &preparedTestProvider{}}
				var authorized, handled atomic.Uint32
				cores, _, _, ctx := handlerCorePairBeforeRun(t, framing, func(role int) RawStreamHandlerConfig {
					return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationResident,
						AuthorizeOpen: func(context.Context, any, []byte) error { authorized.Add(1); return nil },
						Handler: func(ctx context.Context, _ any, _ []byte, _ *StreamOwnership) error {
							handled.Add(1)
							<-ctx.Done()
							return ctx.Err()
						}}
				}, nil, func(cores [2]*SessionCore) {
					host = newEnvironmentSession(&Environment{}, 0, context.Background())
					host.core = cores[1]
					guarantees, _ := provider.ConnectionGuarantees()
					host.info = protocolv4.V4SessionInfo{ApplicationProfile: protocolv4.V4ApplicationProfileTransport, Guarantees: guarantees}
					host.admission = &SessionAdmissionReservation{prepared: &PreparedCarrier{&preparedCarrier{provider: provider, guarantees: guarantees}}}
					close(host.ready)
					if err := cores[1].Runtime().bindApplicationPublication(host.published); err != nil {
						t.Fatal(err)
					}
				})
				opening := make(chan factoryStreamResult, 1)
				openContext, cancelOpen := context.WithCancel(ctx)
				defer cancelOpen()
				awaitOpening := func() factoryStreamResult {
					select {
					case result := <-opening:
						return result
					case <-ctx.Done():
						t.Fatal("original opening did not finish")
						return factoryStreamResult{}
					}
				}
				go func() {
					stream, err := cores[0].OpenStream(openContext, "example/raw", nil, streamTestDeadline(t, cores[0].Engine()))
					opening <- factoryStreamResult{stream, err}
				}()
				a := cores[1].Admission()
				waitCoreOpen(t, a, OpenHandle{a, 1}, true)
				if authorized.Load() != 0 || handled.Load() != 0 {
					t.Fatal("READY/staged OPEN bypassed host publication")
				}
				// PING/PONG remains on the original runtime while application
				// handoff is pending, without a second decoder or worker.
				before, err := cores[1].Engine().ScopeFrontier(0, protocolv4.ServerToClient)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cores[0].plan.writer.Write(ctx, protocolv4.FramePing, pingBody(t, 7)); err != nil {
					t.Fatal(err)
				}
				for {
					after, err := cores[1].Engine().ScopeFrontier(0, protocolv4.ServerToClient)
					if err != nil {
						t.Fatal(err)
					}
					if after.Sequence > before.Sequence {
						break
					}
					if ctx.Err() != nil {
						t.Fatal("publication blocked maintenance")
					}
					runtime.Gosched()
				}
				if authorized.Load() != 0 || handled.Load() != 0 {
					t.Fatal("maintenance opened application gate")
				}
				if err := cores[1].Runtime().bindApplicationPublication(make(chan struct{})); !errors.Is(err, cryptov4.ErrTransition) {
					t.Fatal("rebound runtime publication", err)
				}
				if publish {
					if session, err := host.deliver(ctx); err != nil || session != host {
						t.Fatal(session, err)
					}
					result := awaitOpening()
					if result.err != nil || result.stream == nil {
						t.Fatal(result.err)
					}
					t.Cleanup(func() { _ = result.stream.Cancel(); _ = result.stream.Release() })
					if authorized.Load() != 1 {
						t.Fatal("missing original authorization")
					}
					if _, err := host.deliver(ctx); !errors.Is(err, cryptov4.ErrTransition) {
						t.Fatal("duplicate host delivery", err)
					}
				} else {
					if outcome == "guarantee_loss" {
						provider.changed.Store(true)
						if session, err := host.deliver(ctx); session != nil || !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) {
							t.Fatal("changed provider passed final publication", err)
						}
					}
					host.closeWith(cryptov4.ErrClosed)
					cores[1].Close()
					cancelOpen()
					result := awaitOpening()
					if result.err == nil || result.stream != nil {
						t.Fatal("unpublished Session produced Stream", result)
					}
					if _, err := host.deliver(ctx); !errors.Is(err, cryptov4.ErrClosed) && !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) {
						t.Fatal("late READY published", err)
					}
					if authorized.Load() != 0 || handled.Load() != 0 {
						t.Fatal("close dispatched original application candidate")
					}
				}
			})
		}
	}
}
