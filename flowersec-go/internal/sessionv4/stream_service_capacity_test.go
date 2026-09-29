package sessionv4

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Actual encrypted Session traffic and external service lifetimes exercise the
// target alongside eight ordinary calls in each direction. This is a runtime
// capacity regression, not a provider/RSS or application workload qualification.
func TestStreamServiceCapacityAlongsideEightOrdinaryStreamsEachDirection(t *testing.T) {
	for _, target := range []uint32{64, 128} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			var fixtures [2]initialCoreFixture
			var executors [2]*ApplicationExecutor
			services := make(chan struct{}, target)
			ordinary := [2]chan struct{}{make(chan struct{}, 8), make(chan struct{}, 8)}
			role := 0
			prepare := initialCorePrepareWithResources(t, &fixtures, false, func(c *SessionCoreConfig) {
				r := role
				f := &fixtures[r]
				ecfg := ApplicationExecutorConfig{Running: 24, ResidentRunning: 18, RuntimeBytes: 32768, RuntimeBytesPerTask: 32768}
				charge, err := ApplicationExecutorCharge(ecfg)
				if err != nil {
					t.Fatal(err)
				}
				executors[r], err = NewApplicationExecutor(ecfg, f.reserve(t, charge))
				if err != nil {
					t.Fatal(err)
				}
				pcfg := StreamHandlerPlanConfig{RuntimeBytes: 32768, Handlers: []RawStreamHandlerConfig{{Kind: "test/short", Slots: 8, WorkClass: ApplicationShort,
					Handler: func(ctx context.Context, _ any, _ []byte, _ *StreamOwnership) error {
						ordinary[r] <- struct{}{}
						<-ctx.Done()
						return ctx.Err()
					}}}}
				if r == 1 {
					pcfg.Handlers = append(pcfg.Handlers, RawStreamHandlerConfig{Kind: "test/service", Slots: target, WorkClass: ApplicationShort,
						Delegated: &DelegatedStreamService{Options: delegatedRawOptions(), Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
							return func(ctx context.Context, _ net.Conn) error {
								services <- struct{}{}
								<-ctx.Done()
								return ctx.Err()
							}, nil
						}}})
				}
				charge, err = StreamHandlerPlanCharge(pcfg)
				if err != nil {
					t.Fatal(err)
				}
				delegate, err := f.environment.Borrow()
				if err != nil {
					t.Fatal(err)
				}
				plan, err := NewStreamHandlerPlan(pcfg, executors[r], f.reserve(t, charge), delegate)
				if err != nil {
					t.Fatal(err)
				}
				c.Streams = factoryStreamConfig()
				c.Streams.ReceivePoolBytes = uint64(target+16) * c.Streams.ReceiveBytes
				c.MaxScopes, c.PendingScopes, c.WorkSlots = target+16, 16, 24
				c.Open.Active, c.Open.Opening, c.Open.IngressItems, c.Open.Terminal = target+16, 8, 16, target+24
				c.Open.PerClass = [3]uint32{target + 16}
				c.Open.PerOpener = [2][3]uint32{{target + 16}, {target + 16}}
				c.Handlers = SessionStreamHandlerConfig{Plan: plan, Concurrency: 8, TimeoutMS: 30000, RuntimeBytes: 32768, RuntimeBytesPerInvocation: 32768}
				if target == 128 {
					c.Handlers.ServiceTarget = target
				}
				role++
			}, func(c *resourcev4.Config) {
				c.ReservationSlots, c.ReferenceSlots = 4096, 8192
				c.Limit = resourcev4.Vector{resourcev4.SDKBytes: 256 << 20, resourcev4.ProviderBytes: 256 << 20, resourcev4.Items: 1 << 20, resourcev4.Tasks: 4096, resourcev4.WorkSlots: 4096, resourcev4.Timers: 4096, resourcev4.Sessions: 2}
			})
			pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, func(h *cryptov4.HandshakeConfig, initial *InitialConfig) {
				h.Session = testSessionContract(t, h.Profile, "transport", 4096, target+16, 0, h.Session.SessionNotAfterMS)
				prepare(h, initial)
			})
			results := startInitialCorePair(pair, configs, &fixtures)
			var cores [2]*SessionCore
			for r := range cores {
				result := waitInitialCoreOutcome(t, results[r])
				if result.err != nil {
					t.Fatal(result.err)
				}
				cores[r] = result.core
			}
			if len(cores[1].plan.serviceFloors) != int(target) {
				t.Fatal("READY omitted service target")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			ended := make(chan error, 2)
			for r := range cores {
				go func() { ended <- cores[r].Runtime().Run(ctx) }()
			}
			t.Cleanup(func() {
				for _, core := range cores {
					core.Close()
				}
				for range cores {
					_ = waitRuntime(t, ended)
				}
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				for r := range cores {
					if err := fixtures[r].plan.Abort(cleanup); err != nil {
						t.Error(err)
					}
					executors[r].Close()
					if err := pair[r].WaitCleanup(cleanup); err != nil {
						t.Error(err)
					}
					if got := fixtures[r].root.Snapshot().Reservations; got != 1 {
						t.Error("actual service tail retained", r, got)
					}
				}
			})
			open := func(source int, kind string) {
				stream, err := cores[source].OpenStream(ctx, kind, nil, streamTestDeadline(t, cores[source].Engine()))
				if err != nil {
					t.Fatal(kind, err)
				}
				t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
			}
			for range target {
				open(0, "test/service")
				select {
				case <-services:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			waitDispatcherServices(t, ctx, cores[1].plan.dispatcher, target)
			if got := executors[1].Snapshot().Running; got != 0 {
				t.Fatal("idle services consumed ordinary permits", got)
			}
			for source := range 2 {
				for range 8 {
					open(source, "test/short")
					select {
					case <-ordinary[1-source]:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
			}
			for _, e := range executors {
				if got := e.Snapshot().Running; got != 8 {
					t.Fatal("ordinary work point was unavailable", got)
				}
			}
		})
	}
}
