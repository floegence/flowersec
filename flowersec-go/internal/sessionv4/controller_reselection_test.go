package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// These Sessions share the admitted clock, authority, executor and result
// root. Distinct RPC owners and publishers exercise immutable routing;
// the unrelated connection-acquisition runtime is never invoked by this fixture.
func controllerReselectionFixture(t *testing.T, sessionCounts ...int) (*serviceDispatchFixture, []*RPCServices, *ConnectionController, []*EnvironmentSession, []*serviceDispatchFixture) {
	t.Helper()
	f, r, _, e := deferredCallerFixture(t)
	r.routes = f.routes
	_, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := newOpenEndpointAuthorization(t, protocolv4.ClientToServer, 4, 4, 1, f.trust.clock, 0, authority)
	count := 4
	if len(sessionCounts) != 0 {
		count = sessionCounts[0]
	}
	if len(sessionCounts) > 1 || count < 2 || count > 4 {
		t.Fatal("invalid finite replacement fixture")
	}
	sessions := make([]*EnvironmentSession, count)
	services := []*RPCServices{r}
	fixtures := []*serviceDispatchFixture{f}
	for j := range sessions {
		if j != 0 {
			peer, next := controllerRPCFixture(t, f, byte(j+1))
			services = append(services, next)
			fixtures = append(fixtures, peer)
		}
		plan := &SessionCorePlan{rpc: services[j], application: f.plan, engine: endpoint.engine, admission: endpoint.admission, config: SessionCoreConfig{Clock: f.trust.clock}}
		sessions[j] = &EnvironmentSession{delivered: true, core: &SessionCore{plan: plan}, admission: &SessionAdmissionReservation{authorization: authority}}
	}
	c := &ConnectionController{identity: &controllerIdentity{}, environment: e, current: sessions[0], changed: make(chan struct{}), wake: make(chan struct{}, 1), reservation: f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.Items: 1})}
	t.Cleanup(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		// The original Environment coordinator can own a closing workload
		// while these finite advances skip it. Join its actual exit instead
		// of treating a fixed number of scheduler passes as cleanup proof.
		ctx := resultTestContext(t)
		for {
			for _, service := range services {
				service.AdvanceCalls()
			}
			e.advanceResults()
			c.advanceDispatches()
			c.mu.Lock()
			pending := c.dispatches
			c.mu.Unlock()
			if pending == 0 {
				return
			}
			select {
			case <-ctx.Done():
				t.Error("Controller retained cleaned route", pending, ctx.Err())
				return
			case <-time.After(time.Millisecond):
			}
		}
	})
	return f, services, c, sessions, fixtures
}

func controllerRPCFixture(t *testing.T, original *serviceDispatchFixture, id byte) (*serviceDispatchFixture, *RPCServices) {
	t.Helper()
	f := *original
	nc := rpcv4.NetworkConfig{Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000).Contract, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, RuntimeBytes: 4096}
	charge, _ := rpcv4.NetworkCharge(nc)
	var err error
	f.network, err = rpcv4.NewNetwork(nc, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.network.Close)
	ic := rpcv4.ServiceInputsConfig{Clock: f.trust.clock, GeneralOutstanding: 32, MaxCaptureBytes: 1048576, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, RuntimeBytes: 4096, Root: f.f.root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{92, id}, Backing: [16]byte{92, id}, Kind: 92}}
	charge, _ = rpcv4.ServiceInputsCharge(ic)
	inputs, err := f.network.NewServiceInputs(f.routes, ic, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inputs.Close)
	f.sink = &queryIntegrationSink{}
	charge, _ = rpcv4.PublisherCharge(4096)
	f.publisher, err = f.network.NewPublisher([16]byte{id}, f.sink, f.f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.publisher.Close)
	charge, _ = rpcv4.ReceiverCharge(4096)
	f.receiver, err = f.network.NewReceiver(f.publisher, inputs, f.f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.receiver.Close)
	_, r, _ := callerForServiceFixture(t, &f)
	r.owner.Instance[1], r.owner.Backing[1] = id, id
	r.routes = f.routes
	_, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = protocolv4.DeliverySubscriptionFloorCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: 4096})
	r.deliveryFloor, err = authority.ReserveDeliveryFloor(f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	environment, err := r.bindingEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	r.shortResultPosition, err = environment.protectResult(environment.reservation)
	if err != nil {
		t.Fatal(err)
	}
	return &f, r
}

func advanceControllerServices(services []*RPCServices) {
	for _, r := range services {
		r.AdvanceCalls()
	}
}

func prepareControllerCall(t *testing.T, c *ConnectionController, f *serviceDispatchFixture, encodes *atomic.Int32, mode uint8) *UnaryOperation {
	t.Helper()
	method := UnaryMethodDefinition{Contract: f.policy.Digest, WorkClass: ApplicationShort, Decode: synchronousResult,
		Codec: SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { encodes.Add(1); return input, nil }}}
	o, err := c.PrepareUnary(context.Background(), method, []byte("original bytes"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024, AdmissionMode: mode})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	return o
}

func switchControllerFixture(c *ConnectionController, s *EnvironmentSession) {
	c.mu.Lock()
	c.current = s
	c.mu.Unlock()
}

func TestControllerQueuedUnaryReselectsBeforeHeaderWithoutReencoding(t *testing.T) {
	f, services, c, sessions, fixtures := controllerReselectionFixture(t)
	var encodes atomic.Int32
	o := prepareControllerCall(t, c, f, &encodes, 0)
	started := c.Dispatch(context.Background(), o)
	if started.Error != nil {
		t.Fatal(started.Error)
	}
	old := started.Call.invocation
	oldPublication := old.publication
	results := make(chan error, 1)
	ctx := resultTestContext(t)
	go func() {
		value, _, err := o.TakeResult(ctx)
		if err == nil && !bytes.Equal(value.([]byte), []byte("response")) {
			err = errors.New("wrong result after route selection")
		}
		results <- err
	}()
	for {
		started.Call.mu.Lock()
		waiting := started.Call.deferred.waiters != 0
		started.Call.mu.Unlock()
		if waiting {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		runtime.Gosched()
	}
	switchControllerFixture(c, sessions[1])
	c.advanceDispatches()
	current := started.Call.currentCall()
	if current == started.Call || o.reselections != 1 || encodes.Load() != 1 {
		t.Fatal("route was not changed within original Start", o.reselections, encodes.Load(), old.publicationFailure)
	}
	if p := oldPublication.Progress(); p.HeaderAccepted || !p.Terminal || p.Reason != "not_submitted" {
		t.Fatal("old route was not permanently withdrawn", p)
	}
	if err := old.WithRequestPublication(o.header, func() error { t.Fatal("old incarnation published"); return nil }); err == nil {
		t.Fatal("stale publication gate remained open")
	}
	if current.request != o.header || current.invocation.deadline.Cap() != old.deadline.Cap() {
		t.Fatal("reselection changed request identity or deadline")
	}
	f.trust.tick.Store(100)
	if remaining, err := current.invocation.deadline.RemainingMS(); err != nil || remaining != 650 {
		t.Fatal("reselection renewed original monotonic deadline", remaining, err)
	}
	finishShortResponse(t, fixtures[1], o.header, 1, []byte("response"))
	advanceControllerServices(services)
	if err := <-results; err != nil {
		t.Fatal(err, current.ResultStatus())
	}
	if started.Call.deferred.cleaned {
		t.Fatal("retained route forwarding metadata was refunded before Close")
	}
	if again := c.Dispatch(context.Background(), o); again.Call != started.Call || again.Error != nil {
		t.Fatal("Dispatch made a second Start", again)
	}
	o.Close()
	advanceControllerServices(services)
	e := c.environment
	e.advanceResults()
	c.advanceDispatches()
	if err := o.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestControllerQueuedUnaryReselectionLimitAndHeaderBoundary(t *testing.T) {
	for _, mode := range []string{"limit", "accepted", "try_now", "closed", "authority", "expired", "capacity", "unrelated_not_ready"} {
		t.Run(mode, func(t *testing.T) {
			f, services, c, sessions, fixtures := controllerReselectionFixture(t)
			var encodes atomic.Int32
			admission := uint8(0)
			if mode == "try_now" {
				admission = 1
			}
			o := prepareControllerCall(t, c, f, &encodes, admission)
			started := c.Dispatch(context.Background(), o)
			if started.Error != nil {
				t.Fatal(started.Error)
			}
			if mode == "accepted" {
				if _, err := f.publisher.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "closed" {
				o.Close()
			}
			if mode == "authority" {
				o.controller.routing.endpoint[0] ^= 1
			}
			if mode == "expired" {
				f.trust.tick.Store(751)
			}
			if mode == "unrelated_not_ready" {
				started.Call.invocation.mu.Lock()
				started.Call.invocation.publicationFailure = cryptov4.ErrNotReady
				started.Call.invocation.mu.Unlock()
			}
			if mode == "capacity" {
				// A short call may use general spare capacity while its floor
				// is held, so exercise exhaustion of both actual vectors.
				saturateServiceRoot(t, f)
				refs := make([]resourcev4.Reference, 6)
				if err := resourcev4.CheckoutProtectedBatch(services[1].shortCaller[:], refs); err != nil {
					t.Fatal(err)
				}
				defer func() {
					for _, ref := range refs {
						ref.Release()
					}
				}()
			}
			for j := 1; j <= 3; j++ {
				switchControllerFixture(c, sessions[j])
				c.advanceDispatches()
				advanceControllerServices(services)
			}
			if mode == "limit" && o.reselections != 2 {
				t.Fatal(o.reselections, started.Call.ResultStatus())
			}
			if mode != "limit" && mode != "capacity" && o.reselections != 0 {
				t.Fatal("ineligible operation rerouted", o.reselections)
			}
			if encodes.Load() != 1 {
				t.Fatal("encoder was repeated")
			}
			if mode == "limit" || mode == "authority" || mode == "capacity" || mode == "unrelated_not_ready" {
				status := started.Call.ResultStatus()
				if !status.Complete || status.Submission.HeaderAccepted {
					t.Fatal(status)
				}
				if mode == "authority" && status.Outcome.Error != ErrApplicationAuthorization {
					t.Fatal(status.Outcome)
				}
				if mode == "capacity" && status.Outcome.Error != resourcev4.ErrCapacity {
					t.Fatal(status.Outcome)
				}
			}
			o.Close()
			for _, fixture := range fixtures {
				fixture.publisher.Close()
				fixture.receiver.Close()
			}
			advanceControllerServices(services)
		})
	}
}

func TestControllerPreparationUsesCurrentAtOriginalStart(t *testing.T) {
	f, services, c, sessions, _ := controllerReselectionFixture(t)
	var encodes atomic.Int32
	o := prepareControllerCall(t, c, f, &encodes, 0)
	switchControllerFixture(c, sessions[1])
	started := c.Dispatch(context.Background(), o)
	if started.Error != nil || o.reselections != 1 {
		t.Fatal(started, o.reselections)
	}
	if started.Call.invocation.controller.session != sessions[1] {
		t.Fatal("Start retained stale Session")
	}
	o.Close()
	advanceControllerServices(services)
	if got := c.Dispatch(context.Background(), o); got.Call != started.Call || got.Error != nil {
		t.Fatal(got)
	}
}
