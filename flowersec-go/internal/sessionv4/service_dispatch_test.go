package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

type serviceDispatchFixture struct {
	f         *executorFixture
	trust     *sessionAdmissionTrustFixture
	plan      *SessionPlan
	dispatch  *ServiceDispatch
	network   *rpcv4.Network
	routes    *rpcv4.ContractRoutes
	publisher *rpcv4.Publisher
	receiver  *rpcv4.Receiver
	sink      *queryIntegrationSink
	policy    protocolv4.ServiceContractPolicy
	codec     *protocolv4.ApplicationHeaderCodec
	serial    uint64
	contract  *protocolv4.ServiceContract
	history   *rpcv4.VolatileExecutions
}

func newServiceDispatchFixture(t *testing.T, handler func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error)) *serviceDispatchFixture {
	return newServiceDispatchFixtureConfigured(t, handler, false, ApplicationShort)
}

func newServiceDispatchFixtureConfigured(t *testing.T, handler func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error), protect bool, class ApplicationWorkClass, completionCapacity ...uint32) *serviceDispatchFixture {
	return newServiceDispatchFixtureProfile(t, handler, protect, class, false, completionCapacity...)
}
func newServiceDispatchFixtureProfile(t *testing.T, handler func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error), protect bool, class ApplicationWorkClass, execution bool, completionCapacity ...uint32) *serviceDispatchFixture {
	return newServiceDispatchFixtureContract(t, handler, protect, class, execution, "service_unary_execution", completionCapacity...)
}
func newServiceDispatchFixtureContract(t *testing.T, handler func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error), protect bool, class ApplicationWorkClass, execution bool, executionContract string, completionCapacity ...uint32) *serviceDispatchFixture {
	t.Helper()
	var limit resourcev4.Vector
	for index := range limit {
		limit[index] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 256, ReferenceSlots: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("service dispatch leaked original resources", root.Snapshot())
		}
	})
	f := &executorFixture{root: root, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 4, ResidentReady: 2, CompletionRunning: 1, CompletionReserved: 2, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	if len(completionCapacity) != 0 {
		f.config.CompletionReserved = completionCapacity[0]
	}
	charge, _ := ApplicationExecutorCharge(f.config)
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitApplicationTask(t, f.executor.Done()) })
	env := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
	trust := newSessionAdmissionTrustFixture(t, root, env, resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83})
	authorization, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authorization.Close(nil) })
	body := initialFixture(t, "service_unary_transient")
	profile := "services"
	if execution {
		profile = "execution"
		body = initialFixture(t, executionContract)
		body = bytes.Replace(body, []byte{0x0d, 0x01}, []byte{0x0d, 0x00}, 1)
	}
	cc, _ := protocolv4.NewServiceContractCodec(256)
	contract, err := cc.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(contract.Release)
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	rc := rpcv4.ContractRoutesConfig{Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{body}}}, ContractNodes: 256, RuntimeBytes: 4096}
	if execution {
		rc.Clock = trust.clock
		rc.Methods[0].OfferWindowMS = 1000
	}
	charge, _ = rpcv4.ContractRoutesCharge(rc)
	routes, err := rpcv4.NewContractRoutes(rc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	if execution {
		var offer [256]byte
		encoded, err := protocolv4.EncodeMap(offer[:], "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: policy.Digest[:]}, {Name: "not_before_ms", Number: 1000}, {Name: "not_after_ms", Number: 2000}})
		if err == nil {
			err = routes.RegisterOffer(policy.Digest, encoded)
		}
		if err != nil {
			t.Fatal("register execution offer", err)
		}
	}
	nc := rpcv4.NetworkConfig{Session: testSessionContract(t, protocolv4.DHProfileX25519, profile, 4096, 4, 0, 5000).Contract, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, RuntimeBytes: 4096}
	if execution {
		nc.ResultRead = rpcv4.QueryBinding{Type: 3, Contract: policy.Digest}
	}
	charge, _ = rpcv4.NetworkCharge(nc)
	network, err := rpcv4.NewNetwork(nc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(network.Close)
	ic := rpcv4.ServiceInputsConfig{Clock: trust.clock, GeneralOutstanding: 32, MaxCaptureBytes: 1048576, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, RuntimeBytes: 4096, Root: root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{92}, Backing: [16]byte{92}, Kind: 92}}
	if protect {
		ic.ShortRequestBytes, ic.ShortResponseBytes = 8192, 8192
		if class == ApplicationShort {
			ic.ShortMethods = []uint32{0}
		}
		inputCharge, e := rpcv4.RequestInputEnvelopeCharge(ic.ShortRequestBytes, rpcv4.InputConfig{Clock: trust.clock, Capture: true, RuntimeBytes: ic.InputRuntimeBytes, HashRuntimeBytes: ic.HashRuntimeBytes})
		if e != nil {
			t.Fatal(e)
		}
		inputCharge, e = resourcev4.ProtectedCharge(inputCharge)
		if e != nil {
			t.Fatal(e)
		}
		ic.ShortReservation = f.reserve(t, 1, inputCharge)
	}
	charge, _ = rpcv4.ServiceInputsCharge(ic)
	inputs, err := network.NewServiceInputs(routes, ic, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inputs.Close)
	sink := &queryIntegrationSink{}
	charge, _ = rpcv4.PublisherCharge(4096)
	publisher, err := network.NewPublisher([16]byte{1}, sink, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = rpcv4.ReceiverCharge(4096)
	receiver, err := network.NewReceiver(publisher, inputs, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	plan := applicationTestPlan(t, f, SessionPlanConfig{Services: true, RuntimeBytes: 4096, ExecutionHistoryNamespaces: []string{policy.Namespace}, AuthorizeApplication: func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		lease, err := c.ReserveLease(c.Binding(), "original context", func(context.Context) error { return nil })
		if err == nil {
			err = lease.SetServiceAccess(policy.Namespace, policy.Type, true)
		}
		if err == nil && execution {
			err = lease.BindExecutionIdentity(c.Binding(), ExecutionSessionIdentity{Tenant: "tenant", Audience: "audience", Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}})
		}
		return AuthorizeApplicationResult{Lease: lease}, err
	}})
	config := ServiceDispatchConfig{Root: root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{94}, Backing: [16]byte{94}, Kind: 94}, Clock: trust.clock, Slots: 4, ResidentSlots: 2, RuntimeBytes: 4096, InvocationRuntimeBytes: 4096, Methods: []UnaryRegistration{{Method: 0, Namespace: policy.Namespace, Type: policy.Type, Handler: handler}}}
	config.Methods[0].WorkClass = class
	if protect {
		config.ShortResponseBytes = 8192
		calls, e := serviceCallCharges(config.InvocationRuntimeBytes, config.ShortResponseBytes, f.executor.TaskCharge())
		if e != nil {
			t.Fatal(e)
		}
		for i, c := range calls {
			c, e = resourcev4.ProtectedCharge(c)
			if e != nil {
				t.Fatal(e)
			}
			config.ShortReservations[i] = f.reserve(t, 1, c)
		}
		config.ShortExecutionBorrow, err = config.ShortReservations[0].Borrow()
		if err != nil {
			t.Fatal(err)
		}
	}
	var history *rpcv4.VolatileExecutions
	if execution {
		owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{120}, Backing: [16]byte{120}, Kind: 12}
		hc := rpcv4.VolatileExecutionConfig{Root: root, Owner: owner, Clock: trust.clock, Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, CallerAuthorities: [][32]byte{{8}}, Records: 16, Active: 4, TaskCharge: f.executor.TaskCharge(), RuntimeBytes: 4096, WorkRuntimeBytes: 4096, ResultRuntimeBytes: 4096}
		charge, err := rpcv4.VolatileExecutionsCharge(hc)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := root.Reserve(owner, charge)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		history, err = rpcv4.NewVolatileExecutions(hc, ref)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(history.Close)
		owner.Instance, owner.Backing = [16]byte{121}, [16]byte{121}
		rc := rpcv4.ServiceRegistryConfig{Root: root, Owner: owner, Entries: 4, RuntimeBytes: 4096}
		charge, err = rpcv4.ServiceRegistryCharge(rc)
		if err != nil {
			t.Fatal(err)
		}
		ref, err = root.Reserve(owner, charge)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		registry, err := rpcv4.NewServiceRegistry(rc, ref)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(registry.Close)
		if err = registry.Bind(rpcv4.ServiceBinding{Authority: rpcv4.ServiceAuthority{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, History: history}); err != nil {
			t.Fatal(err)
		}
		config.ExecutionRegistry = registry
		if protect && class == ApplicationShort {
			config.ExecutionServices = []rpcv4.ServiceBinding{{Authority: rpcv4.ServiceAuthority{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}, History: history}}
			output, err := executionCallCharges(config.InvocationRuntimeBytes, config.ShortResponseBytes)
			if err != nil {
				t.Fatal(err)
			}
			for i, vector := range output {
				vector, err = resourcev4.ProtectedCharge(vector)
				if err != nil {
					t.Fatal(err)
				}
				config.ShortExecutionReservations[i] = f.reserve(t, 1, vector)
			}
			admission, err := history.ShortAdmissionCharges(config.ShortResponseBytes, config.InvocationRuntimeBytes)
			if err != nil {
				t.Fatal(err)
			}
			config.ShortExecutionAdmissions = make([][4]resourcev4.Reference, 1)
			for i, vector := range admission {
				config.ShortExecutionAdmissions[0][i] = f.reserve(t, 1, vector)
			}
		}
	}
	charge, err = ServiceDispatchCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := plan.InstallServices(config, network, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal("install services", profile, policy, err)
	}
	plan.claimed = true
	if err := plan.authorize(context.Background(), ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt, ApplicationProfile: profile}, authorization.Check); err != nil {
		t.Fatal(err)
	}
	if err := plan.lease.bindAuthorization(authorization); err != nil {
		t.Fatal(err)
	}
	dispatch.activate()
	t.Cleanup(func() {
		plan.Close()
		receiver.Close()
		publisher.Close()
		if err := publisher.Retire(); err != nil {
			t.Error(err)
		}
		until := time.Now().Add(3 * time.Second)
		for {
			dispatch.Advance()
			select {
			case <-dispatch.done:
				return
			default:
			}
			if time.Now().After(until) {
				t.Error("service dispatch retained callback or provider tail")
				return
			}
			runtime.Gosched()
		}
	})
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	return &serviceDispatchFixture{contract: contract, history: history, f: f, trust: trust, plan: plan, dispatch: dispatch, network: network, routes: routes, publisher: publisher, receiver: receiver, sink: sink, policy: policy, codec: codec}
}
func (f *serviceDispatchFixture) request(t *testing.T, payload []byte, mode uint8, deadline uint64) {
	t.Helper()
	f.serial++
	var header [512]byte
	size, _, err := f.codec.Encode(header[:], "transient_unary_request", protocolv4.ApplicationHeaderFields{Type: f.policy.Type, PayloadBytes: uint32(len(payload)), DeadlineAtMS: deadline, ServiceContractDigest: f.policy.Digest, AdmissionMode: mode, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	var wire [4096]byte
	fragments := []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: f.serial, Header: header[:size]}}
	if len(payload) != 0 {
		fragments = append(fragments, protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: f.serial, Payload: payload})
	}
	for _, fragment := range fragments {
		n, err := protocolv4.EncodeRPCFragment(wire[:], fragment)
		if err != nil {
			t.Fatal(err)
		}
		if used, err := f.receiver.Feed(wire[:n]); err != nil || used != n {
			t.Fatal(used, err)
		}
	}
}
func (f *serviceDispatchFixture) response(t *testing.T) (protocolv4.ApplicationHeader, []byte) {
	t.Helper()
	var header protocolv4.ApplicationHeader
	var body []byte
	until := time.Now().Add(3 * time.Second)
	for {
		f.dispatch.Advance()
		progressed, err := f.publisher.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !progressed {
			if time.Now().After(until) {
				t.Fatal("original response did not progress")
			}
			runtime.Gosched()
			continue
		}
		fragment, err := protocolv4.DecodeRPCFragment(f.sink.wire)
		if err != nil {
			t.Fatal(err)
		}
		if fragment.Kind == protocolv4.RPCBegin {
			header, err = f.codec.Decode(fragment.Header)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			body = append(body, fragment.Payload...)
		}
		if header.Kind() != "" && uint32(len(body)) == header.Fields().PayloadBytes {
			if _, err := f.publisher.Step(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.dispatch.Advance()
			return header, body
		}
	}
}
func TestServiceDispatchRealInputAndResponseUseOneOriginalOrdinaryPermit(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixture(t, func(ctx context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
		calls.Add(1)
		input, _, err := r.Input.Bytes()
		if err != nil {
			return 0, err
		}
		if r.ApplicationContext != "original context" || !r.OutputInterest.Interested() {
			t.Error("missing original invocation context")
		}
		_, err = w.Write(append([]byte("reply:"), input...))
		return 0, err
	})
	f.request(t, []byte("hello"), 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	header, body := f.response(t)
	if header.Kind() != "transient_unary_response" || !bytes.Equal(body, []byte("reply:hello")) || calls.Load() != 1 {
		t.Fatal(header.Kind(), body, calls.Load())
	}
}
func TestServiceDispatchTryNowRefusesAndQueuedCancellationKeepsInput(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixture(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { calls.Add(1); return 0, nil })
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	f.request(t, nil, 1, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("try-now queued", err)
	}
	header, body := f.response(t)
	if !header.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, 5}) {
		t.Fatal(header.Kind(), body)
	}
	f.request(t, []byte("original"), 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || f.f.executor.Snapshot().Ready != 1 {
		t.Fatal("queued callback started early")
	}
	if err := f.plan.lease.SetServiceAccess(f.policy.Namespace, f.policy.Type, false); err != nil {
		t.Fatal(err)
	}
	f.dispatch.Advance()
	header, body = f.response(t)
	if !header.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, 7}) {
		t.Fatal(header.Kind(), body)
	}
	if calls.Load() != 0 {
		t.Fatal("revoked queue dispatched callback")
	}
	a.Close()
	b.Close()
}
func TestServiceDispatchDeadlineClosesOutputButRetainsActualCallback(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f := newServiceDispatchFixture(t, func(ctx context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
		close(entered)
		<-release
		if _, err := w.Write([]byte("late")); err == nil {
			t.Error("late callback published output")
		}
		if ctx.Err() == nil {
			t.Error("deadline did not cancel original invocation")
		}
		if _, _, err := r.Input.Bytes(); err != nil {
			t.Error("deadline refunded live input borrow", err)
		}
		return 0, nil
	})
	f.request(t, []byte("input"), 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	f.trust.tick.Add(2000)
	f.dispatch.Advance()
	header, body := f.response(t)
	if !header.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, 8}) {
		t.Fatal(header.Kind(), body)
	}
	if f.f.executor.Snapshot().Running != 1 {
		t.Fatal("deadline refunded running callback")
	}
	f.dispatch.mu.Lock()
	active := f.dispatch.active
	f.dispatch.mu.Unlock()
	if active != 1 {
		t.Fatal("deadline dropped actual invocation tail")
	}
	once.Do(func() { close(release) })
	waitExecutorIdle(t, f.f.executor)
	f.dispatch.Advance()
}
func TestServiceDispatchPanicAndGoexitReleaseOnceWithOriginalRefusal(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceDispatchFixture(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) {
				if mode == "panic" {
					panic("private")
				}
				runtime.Goexit()
				return 0, nil
			})
			f.request(t, nil, 0, 2000)
			if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
				t.Fatal(err)
			}
			header, body := f.response(t)
			if !header.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, 9}) {
				t.Fatal(header.Kind(), body)
			}
		})
	}
}

func TestServiceDispatchEnvironmentCoordinatorRunsAndCleansOriginalOwners(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f := newServiceDispatchFixture(t, func(ctx context.Context, _ UnaryRequest, w *UnaryResponse) (uint32, error) {
		close(entered)
		<-release
		_, err := w.Write([]byte("done"))
		return 0, err
	})
	c := EnvironmentConfig{Services: true, Positions: 1, Clock: f.trust.clock, RuntimeBytes: 65536}
	charge, err := EnvironmentCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	dependency := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
	e, err := NewEnvironment(c, f.f.reserve(t, 1, charge), dependency)
	if err != nil {
		t.Fatal(err)
	}
	// This component fixture supplies a delivered wrapper; real handshake/profile
	// admission remains covered by the complete services assembly integration.
	s := newEnvironmentSession(e, 0, context.Background())
	s.application = f.plan
	s.delivered = true
	e.mu.Lock()
	e.positions[0] = s
	e.active = 1
	e.mu.Unlock()
	t.Cleanup(func() {
		e.mu.Lock()
		e.positions[0] = nil
		e.active = 0
		e.mu.Unlock()
		e.Close()
		e.signalMaterials()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
	if err := f.dispatch.AttachChannel(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	f.request(t, nil, 0, 2000)
	e.signalMaterials()
	awaitApplicationTask(t, entered)
	once.Do(func() { close(release) })
	header, body := f.response(t)
	if header.Kind() != "transient_unary_response" || !bytes.Equal(body, []byte("done")) {
		t.Fatal(header.Kind(), body)
	}
	until := time.Now().Add(3 * time.Second)
	for {
		f.dispatch.mu.Lock()
		active := f.dispatch.active
		f.dispatch.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("coordinator retained completed invocation")
		}
		runtime.Gosched()
	}
}

func TestServiceDispatchClaimsOriginalNetworkWithoutManualBypass(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixture(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { calls.Add(1); return 0, nil })
	f.request(t, nil, 0, 2000)
	if _, _, err := f.receiver.NextRequest(); !errors.Is(err, rpcv4.ErrOwner) {
		t.Fatal("manual receiver bypassed original dispatcher", err)
	}
	if _, err := f.network.ClaimServiceConsumer(f.plan.reservation); !errors.Is(err, rpcv4.ErrOwner) {
		t.Fatal("network gained second dispatcher", err)
	}
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	header, _ := f.response(t)
	if header.Kind() != "transient_unary_response" || calls.Load() != 1 {
		t.Fatal(header.Kind(), calls.Load())
	}
}
func TestServiceDispatchPreservesInputDeadlineBeforeApplicationAdmission(t *testing.T) {
	var calls atomic.Uint32
	f := newServiceDispatchFixture(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { calls.Add(1); return 0, nil })
	f.request(t, []byte("complete but undispatched"), 0, 1200)
	f.trust.tick.Add(300)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err == nil {
		t.Fatal("expired input acquired application dispatch")
	}
	header, body := f.response(t)
	if !header.IsSDKError() || !bytes.Equal(body, []byte{0xa1, 0, 8}) || calls.Load() != 0 {
		t.Fatal(header.Kind(), body, calls.Load())
	}
}
