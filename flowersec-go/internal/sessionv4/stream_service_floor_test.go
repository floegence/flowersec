package sessionv4

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Build the real registry and executor with exactly the projected core vector
// and reference capacity. The temporary descriptor is used only to calculate
// charge before the root exists; it never becomes executable authority.
func serviceFloorFixture(t *testing.T, shortage string) (SessionCoreConfig, *resourcev4.Root, resourcev4.Reference, resourcev4.OwnerKey, SessionResourceScope) {
	t.Helper()
	c := corePlanUnitConfig(t, false)
	c.Streams = factoryStreamConfig()
	ecfg := ApplicationExecutorConfig{Running: 4, ResidentRunning: 3, RuntimeBytes: 8192, RuntimeBytesPerTask: 16384}
	pcfg := StreamHandlerPlanConfig{RuntimeBytes: 8192, Handlers: []RawStreamHandlerConfig{{Kind: "test/service", Slots: 2,
		Delegated: &DelegatedStreamService{Options: delegatedRawOptions(), Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
			return func(context.Context, net.Conn) error { return nil }, nil
		}}}}}
	c.Handlers = SessionStreamHandlerConfig{Concurrency: 2, TimeoutMS: 1000, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 16384,
		Plan: &StreamHandlerPlan{executor: &ApplicationExecutor{config: ecfg}, registrations: []streamHandlerRegistration{{config: pcfg.Handlers[0]}}}}
	coreCharge, owners, err := SessionCoreRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	references, err := SessionCoreReferenceSlots(c)
	if err != nil {
		t.Fatal(err)
	}
	executorCharge, err := ApplicationExecutorCharge(ecfg)
	if err != nil {
		t.Fatal(err)
	}
	planCharge, err := StreamHandlerPlanCharge(pcfg)
	if err != nil {
		t.Fatal(err)
	}
	limit, _ := coreCharge.Add(executorCharge)
	limit, _ = limit.Add(planCharge)
	limit, _ = limit.Add(resourcev4.Vector{resourcev4.Items: 1})
	cfg := resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: owners + 3, ReferenceSlots: references + 4}
	switch shortage {
	case "bytes":
		cfg.Limit[resourcev4.ProviderBytes]--
	case "tasks":
		cfg.Limit[resourcev4.Tasks]--
	case "references":
		cfg.ReferenceSlots--
	}
	backing, err := resourcev4.BackingBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Limit[resourcev4.SDKBytes] += backing
	r, err := resourcev4.NewRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	key := resourcev4.OwnerKey{ProfileRevision: cfg.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := r.Reserve(key, resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	key.Backing[0]++
	executorRef, err := r.Reserve(key, executorCharge)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewApplicationExecutor(ecfg, executorRef)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	key.Backing[0]++
	planRef, err := r.Reserve(key, planCharge)
	if err != nil {
		t.Fatal(err)
	}
	delegate, err := environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	c.Handlers.Plan, err = NewStreamHandlerPlan(pcfg, e, planRef, delegate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Handlers.Plan.Close()
		if err := c.Handlers.Plan.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
		if err := c.Handlers.Plan.Retire(); err != nil {
			t.Error(err)
		}
	})
	key.Backing[0]++
	return c, r, environment, key, corePlanTestScope(t, r, cfg.Limit, 1)
}

func TestStreamServiceFloorRejectsIncompleteCapacityBeforeClaim(t *testing.T) {
	for _, shortage := range []string{"bytes", "tasks", "references", "receive", "credit"} {
		t.Run(shortage, func(t *testing.T) {
			c, root, environment, key, scope := serviceFloorFixture(t, shortage)
			want := resourcev4.ErrCapacity
			if shortage == "receive" {
				c.Streams.ReceivePoolBytes = c.Streams.ReceiveBytes
				want = cryptov4.ErrConfiguration
			}
			if shortage == "credit" {
				c.Session = testSessionContract(t, c.Session.Profile, "transport", 4096, 4, 0, c.Session.SessionNotAfterMS, 64)
				want = cryptov4.ErrConfiguration
			}
			before := root.Snapshot()
			if p, err := NewSessionCorePlan(c, root, key, environment, scope); p != nil || !errors.Is(err, want) {
				t.Fatal(p, err, want)
			}
			if root.Snapshot() != before {
				t.Fatal("failed preparation retained resources", before, root.Snapshot())
			}
			if c.Handlers.Plan.claimed {
				t.Fatal("failed capacity consumed registration")
			}
		})
	}
}

func TestStreamServiceFloorReservesReferenceGeometryAndRetainsReceiveTail(t *testing.T) {
	c, root, environment, key, scope := serviceFloorFixture(t, "")
	before := root.Snapshot()
	charge, owners, _ := SessionCoreRequirements(c)
	references, _ := SessionCoreReferenceSlots(c)
	p, err := NewSessionCorePlan(c, root, key, environment, scope)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCorePlanUnit(t, p)
	expected, _ := before.Charged.Add(charge)
	if got := root.Snapshot(); got.Charged != expected || got.Reservations != before.Reservations+owners || got.References != before.References+references {
		t.Fatal("incomplete original floor", got)
	}
	if _, err := environment.Borrow(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("reference projection was not exact", err)
	}
	f := &p.serviceFloors[0]
	refs, err := f.checkout()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := f.receive.newFlow(1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		ref.Release()
	}
	if _, err := f.checkout(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("reused before actual receive cleanup", err)
	}
	if err := flow.releaseUnpublished(true); err != nil {
		t.Fatal(err)
	}
	refs, err = f.checkout()
	if err != nil {
		t.Fatal("actual cleanup did not return original floor", err)
	}
	for _, ref := range refs {
		ref.Release()
	}
}

func TestStreamServiceFloorRunsAndReusesWithoutFreeRootReferences(t *testing.T) {
	var held []resourcev4.Reference
	defer func() {
		for _, ref := range held {
			ref.Release()
		}
	}()
	cores, fixtures, _, ctx := handlerCorePairBeforeRun(t, "stream", func(int) RawStreamHandlerConfig {
		return RawStreamHandlerConfig{Kind: "test/service", Slots: 1, Delegated: &DelegatedStreamService{Options: delegatedRawOptions(),
			Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
				return func(_ context.Context, conn net.Conn) error {
					var b [8]byte
					if _, err := io.ReadFull(conn, b[:]); err != nil {
						return err
					}
					var tail [1]byte
					if n, err := conn.Read(tail[:]); n != 0 || !errors.Is(err, io.EOF) {
						return io.ErrUnexpectedEOF
					}
					_, err := conn.Write(b[:])
					return err
				}, nil
			}}}
	}, func(_ int, c *SessionStreamHandlerConfig) { c.ServiceTarget = 1 }, func(cores [2]*SessionCore) {
		for {
			ref, err := cores[1].plan.refs[corePlanOwner].Borrow()
			if errors.Is(err, resourcev4.ErrCapacity) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, ref)
		}
	})
	before := fixtures[1].root.Snapshot()
	for round := range 3 {
		stream, err := cores[0].OpenStream(ctx, "test/service", nil, streamTestDeadline(t, cores[0].Engine()))
		if err != nil {
			t.Fatalf("round %d OPEN: %v", round, err)
		}
		t.Cleanup(func() { _ = stream.Cancel(); _ = stream.Release() })
		if _, err := stream.WriteAll(ctx, []byte("service!")); err != nil {
			t.Fatal(err)
		}
		if err := stream.CloseWrite(ctx); err != nil {
			t.Fatal(err)
		}
		var body [8]byte
		filled := 0
		for {
			var b [8]byte
			r, err := stream.ReadInto(ctx, b[:])
			if err != nil {
				t.Fatal(err)
			}
			filled += copy(body[filled:], b[:r.Progress.Filled])
			if r.ReadTerminal == protocolv4.V4ReadTerminalEof {
				break
			}
		}
		if filled != 8 || string(body[:]) != "service!" {
			t.Fatal("wrong payload", body)
		}
		if err := stream.Finish(ctx); err != nil {
			t.Fatal(err)
		}
		waitDispatcherServices(t, ctx, cores[1].plan.dispatcher, 0)
		if err := stream.Release(); err != nil {
			t.Fatal(err)
		}
		if after := fixtures[1].root.Snapshot(); after != before {
			t.Fatal("service changed original floor geometry", before, after)
		}
	}
}
