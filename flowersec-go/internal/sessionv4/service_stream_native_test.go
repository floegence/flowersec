package sessionv4

import (
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func TestServiceStreamNativeConvenienceTransfersOriginalOwner(t *testing.T) {
	serviceStreamNativeConvenience(t, false, false)
}

func TestServiceStreamNativeInvocationChecksOutOriginalPreacceptedStream(t *testing.T) {
	serviceStreamNativeConvenience(t, true, false)
}

func TestServiceStreamNativeRequiredDeclarationPreparesOriginalPool(t *testing.T) {
	serviceStreamNativeConvenience(t, true, true)
}

func TestServiceStreamNativeEncodedItemsRefillSelectedEnvelope(t *testing.T) {
	serviceStreamNativeConvenience(t, false, false, true)
}

func TestServiceStreamNativeWorkloadUsesOriginalVectorAtFullRoot(t *testing.T) {
	serviceStreamNativeConvenience(t, false, false, false, true)
}

func TestServiceStreamNativePreacceptedWorkloadUsesOriginalVectorAtFullRoot(t *testing.T) {
	serviceStreamNativeConvenience(t, true, false, false, true)
}

func serviceStreamNativeConvenience(t *testing.T, preaccepted, required bool, encoded ...bool) {
	t.Helper()
	body := initialFixture(t, "service_stream_transient")
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.Policy()
	contract.Release()
	if err != nil {
		t.Fatal(err)
	}
	var fixtures [2]*executorFixture
	var environments [2]*Environment
	handlerResult := make(chan error, 2)
	handler := func(ctx context.Context, request StreamRequest, response *StreamMessages) (_ uint32, failure error) {
		defer func() { handlerResult <- failure }()
		input, _, err := request.Input.Bytes()
		if err != nil {
			return 0, err
		}
		if string(input) != "events" {
			return 0, errors.New("changed stream request")
		}
		for _, item := range []string{"one", "two"} {
			if err = response.SendItemEncoded(ctx, []byte(item), 0); err != nil {
				return 0, err
			}
		}
		return 0, nil
	}
	cores, ctx := nativeTransportCorePairConfigured(t, protocolv4.DHProfileX25519, func(role int, f *executorFixture, plan *SessionPlan, config *RPCServicesConfig) {
		fixtures[role] = f
		config.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{body}}}
		config.StreamSlots = 1
		config.StreamMethods = []StreamRegistration{{Method: 0, Namespace: policy.Namespace, Type: policy.Type, ContractDigest: policy.Digest, Kind: "test/events", Handler: handler}}
		cfg := EnvironmentConfig{Services: true, ResultOwners: 16, Positions: 1, Clock: config.Clock, RuntimeBytes: 65536}
		charge, err := EnvironmentCharge(cfg)
		if err != nil {
			t.Fatal(err)
		}
		environments[role], err = NewEnvironment(cfg, f.reserve(t, 1, charge), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			e := environments[role]
			e.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := e.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := e.Retire(); err != nil {
				t.Error(err)
			}
		})
	}, "services")
	authorizeNativeServicePair(t, ctx, cores, fixtures, environments, policy)
	definition := ServiceDefinition{Namespace: policy.Namespace, Methods: []ServiceMethod{{Type: policy.Type, Shape: 1, StreamKind: "test/events", Method: UnaryMethodDefinition{Contract: policy.Digest, Decode: func(_ context.Context, bytes []byte) (any, error) { return string(bytes), nil }, DefaultResponseLimitBytes: 1024}}}}
	bindOptions := UnaryServiceBindOptions{}
	if len(encoded) > 1 && encoded[1] {
		bindOptions.Workloads = []ServiceMethodWorkload{{Type: policy.Type, Calls: 1, RequestBytes: 6}}
	}
	client, err := cores[0].plan.rpc.bindMethods(ctx, definition, bindOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if len(encoded) > 1 && encoded[1] {
		r := cores[0].plan.rpc
		w := client.methods[0].definition.Method.workload
		if w == nil {
			t.Fatal("Bind did not qualify the streaming workload")
		}
		saturateWorkloadRoot(t, &serviceDispatchFixture{f: fixtures[0]})
		if preaccepted {
			op, err := client.PrepareStreamingMethod(ctx, policy.Type, []byte("events"), rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000, ExplicitAdmissionMode: true, AdmissionMode: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			if result := op.Start(ctx); !result.NotAdmitted || !errors.Is(result.Error, cryptov4.ErrNotReady) || result.Stream != nil {
				t.Fatal("try_now miss consumed Start or opened a Stream", result)
			}
			prepareWorkloadPreaccepted(t, ctx, cores[0], policy.Digest, w.slots[0].transport)
			if result := op.Start(ctx); result.Error != nil || result.NotAdmitted || result.Stream == nil {
				t.Fatal("original prepared Start did not consume its preaccepted floor", result)
			}
			consumeNativeStreamOperation(t, ctx, cores, client, op, handlerResult, false, encoded...)
		} else {
			consumeNativeServiceStream(t, ctx, cores, client, policy.Type, handlerResult, false, encoded...)
		}
		for {
			environments[0].advanceResults()
			r.AdvanceCalls()
			r.mu.Lock()
			reusable := !w.slots[0].used
			r.mu.Unlock()
			if reusable {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("original streaming vector did not return", ctx.Err())
			}
			runtime.Gosched()
		}
		if preaccepted {
			prepareWorkloadPreaccepted(t, ctx, cores[0], policy.Digest, w.slots[0].transport)
			encoded = append(encoded, true)
		}
		consumeNativeServiceStream(t, ctx, cores, client, policy.Type, handlerResult, true, encoded...)
		return
	}
	if preaccepted {
		core := cores[0]
		if required {
			declarations := []ServiceDependency{{Alias: "events", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: policy.Namespace, Type: policy.Type}}}}}
			invocationDeclarations(t, fixtures[0], declarations)
			// Repeated aliases share the same actual empty Stream.
			invocationDeclarations(t, fixtures[0], declarations)
		} else {
			if err := core.PreacceptServiceStream(ctx, "test/events", nil, policy.Digest, streamTestDeadline(t, core.plan.engine)); err != nil {
				t.Fatal(err)
			}
		}
		for {
			if err := core.plan.checkPreaccepted(ctx, "test/events", nil, policy.Digest); err == nil {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("preaccepted Stream did not become ready", ctx.Err())
			}
			runtime.Gosched()
		}
		core.plan.mu.Lock()
		entries := 0
		for _, entry := range core.plan.preaccepted {
			if entry != nil {
				entries++
			}
		}
		core.plan.mu.Unlock()
		if entries != 1 {
			t.Fatal("duplicate required targets opened extra Streams", entries)
		}
		select {
		case err := <-handlerResult:
			t.Fatal("empty preaccepted Stream dispatched application code", err)
		default:
		}
		if err := core.plan.checkPreaccepted(ctx, "test/events", []byte("different"), policy.Digest); err == nil {
			t.Fatal("preaccepted Stream ignored exact metadata binding")
		}
		// Keep the real ordinary invocation alive through first publication
		// and consumption; an escaped context cannot authorize a late BEGIN.
		f := fixtures[0]
		backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
		permit, err := f.executor.TryAcquire(ApplicationShort, f.reserve(t, 1, f.executor.TaskCharge()), backing)
		if err != nil {
			t.Fatal(err)
		}
		defer permit.Close()
		if err := permit.runInline(func() {
			application, exit, err := enterApplicationContext(ctx, f.executor, ordinaryApplicationLane, ApplicationShort, backing, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer exit()
			consumeNativeServiceStream(t, application, cores, client, policy.Type, handlerResult, !required)
		}); err != nil {
			t.Fatal(err)
		}
		if required {
			select {
			case err := <-handlerResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("original handler did not complete", ctx.Err())
			}
			for core.plan.checkPreaccepted(ctx, "test/events", nil, policy.Digest) != nil {
				if ctx.Err() != nil {
					client.mu.Lock()
					var state dependencyPathPreparation
					if len(client.methods) != 0 {
						state = client.methods[0].dependencyPath
					}
					client.mu.Unlock()
					var deadlineError error
					if state.deadline != nil {
						deadlineError = state.deadline.Check()
					}
					t.Fatal("required pool did not replenish after checkout", ctx.Err(), state.failure, deadlineError)
				}
				runtime.Gosched()
			}
			select {
			case err := <-handlerResult:
				t.Fatal("replenishment entered an application handler", err)
			default:
			}
		} else if err := core.plan.checkPreaccepted(ctx, "test/events", nil, policy.Digest); err == nil {
			t.Fatal("checkout left a reusable or replenished Stream")
		}
		return
	}
	consumeNativeServiceStream(t, ctx, cores, client, policy.Type, handlerResult, true, encoded...)
}

func consumeNativeServiceStream(t *testing.T, ctx context.Context, cores [2]*SessionCore, client *UnaryServiceClient, method uint32, handlerResult <-chan error, closeBinding bool, encoded ...bool) {
	t.Helper()
	options := rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000}
	if len(encoded) > 1 && encoded[1] {
		options.ExplicitAdmissionMode = true
	}
	if len(encoded) > 2 && encoded[2] {
		options.AdmissionMode, options.ExplicitAdmissionMode = 1, true
	}
	op, err := client.StreamMethod(ctx, method, []byte("events"), options)
	if err != nil {
		t.Fatal("stream preparation/Start", err)
	}
	consumeNativeStreamOperation(t, ctx, cores, client, op, handlerResult, closeBinding, encoded...)
}

func consumeNativeStreamOperation(t *testing.T, ctx context.Context, cores [2]*SessionCore, client *UnaryServiceClient, op *StreamOperation, handlerResult <-chan error, closeBinding bool, encoded ...bool) {
	t.Helper()
	t.Cleanup(op.Close)
	messages, err := op.messages()
	if err != nil {
		t.Fatal(err)
	}
	messages.mu.Lock()
	environment := messages.environment
	messages.mu.Unlock()
	if environment == nil || environment.OperationsSnapshot().ActiveResults != 1 {
		t.Fatal("native streaming escaped the original Environment result table")
	}
	if closeBinding {
		client.Close()
		// A binding-cleanup observer has its own admission and is outside
		// the declared call vector. Under full-root saturation, inspect the
		// actual binding state without requesting another observer alias.
		if len(encoded) > 1 && encoded[1] {
			for !client.advance() {
				if ctx.Err() != nil {
					t.Fatal("binding kept a transferred protected stream", ctx.Err())
				}
				runtime.Gosched()
			}
		} else if err := client.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"one", "two"} {
		var value any
		var status StreamMessageStatus
		if len(encoded) != 0 && encoded[0] {
			messages, e := op.messages()
			if e != nil {
				t.Fatal(e)
			}
			if _, e := messages.captureNext(ctx, false); e != nil {
				t.Fatal(e)
			}
			messages.mu.Lock()
			capacity := cap(messages.input)
			messages.mu.Unlock()
			if capacity != 1024 {
				t.Fatal("item refill ignored selected limit", capacity)
			}
			var input []byte
			input, status, err = op.ReadNextEncoded(ctx)
			value = string(input)
		} else {
			value, status, err = op.ReadNext(ctx)
		}
		if err != nil || value != want {
			select {
			case outcome := <-handlerResult:
				t.Log("handler result", outcome)
			default:
				t.Log("handler did not return")
			}
			t.Fatalf("stream item: %v, %v; want %q; status %+v", value, err, want, status)
		}
	}
	if _, status, err := op.ReadNext(ctx); !errors.Is(err, io.EOF) || !status.EOF {
		t.Fatal(status, err)
	}
	op.Close()
	// This component fixture supplies the host link without Environment
	// admission. Join the real stream tail, then advance the existing RPC
	// coordinator exactly as Environment.advanceServiceDispatches does.
	messages, err = op.messages()
	if err != nil {
		t.Fatal(err)
	}
	if err := messages.waitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	cores[0].plan.rpc.AdvanceCalls()
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func prepareWorkloadPreaccepted(t *testing.T, ctx context.Context, core *SessionCore, digest [32]byte, floor *streamCallerFloor) {
	t.Helper()
	if err := core.preacceptServiceStream(ctx, "test/events", nil, digest, streamTestDeadline(t, core.plan.engine), false, floor.workload); err != nil {
		t.Fatal("preacceptance requested a second transport vector", err)
	}
	for core.plan.checkPreaccepted(ctx, "test/events", nil, digest) != nil {
		if ctx.Err() != nil {
			t.Fatal("preaccepted workload did not become ready", ctx.Err())
		}
		runtime.Gosched()
	}
	if err := core.plan.checkPreaccepted(ctx, "test/events", nil, digest, (*unaryWorkload)(nil)); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal("ordinary readiness borrowed another binding's protected stream", err)
	}
	if err := core.plan.checkPreaccepted(ctx, "test/events", nil, digest, &unaryWorkload{}); !errors.Is(err, cryptov4.ErrNotReady) {
		t.Fatal("independent workload borrowed another binding's protected stream", err)
	}
	core.plan.mu.Lock()
	entry := floor.preaccepted
	if entry == nil || entry.allocation.callerFloor != floor {
		core.plan.mu.Unlock()
		t.Fatal("explicit preacceptance did not use the original workload transport")
	}
	core.plan.mu.Unlock()
}

func authorizeNativeServicePair(t *testing.T, ctx context.Context, cores [2]*SessionCore, fixtures [2]*executorFixture, environments [2]*Environment, policy protocolv4.ServiceContractPolicy, unary ...bool) {
	t.Helper()
	for role, core := range cores {
		r := core.plan.rpc
		plan, f := r.plan, fixtures[role]
		host := newEnvironmentSession(environments[role], 0, context.Background())
		plan.mu.Lock()
		plan.host = host
		plan.mu.Unlock()
		host.mu.Lock()
		host.core, host.delivered = core, true
		host.mu.Unlock()
		backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
		owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83}
		var trust *sessionAdmissionTrustFixture
		if len(unary) != 0 && unary[0] {
			trust = newSessionAdmissionTrustProfile(t, f.root, backing, owner, "live_authority", "transport", r.clock)
		} else {
			trust = newSessionAdmissionTrustFixture(t, f.root, backing, owner)
		}
		authorization, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { authorization.Close(nil) })
		if len(unary) != 0 && unary[0] {
			r.shortResultPosition, err = environments[role].protectResult(environments[role].reservation)
			if err != nil {
				t.Fatal(err)
			}
			r.deliveryFloor, err = authorization.ReserveDeliveryFloor(r.refs[rpcServicesDeliveryFloor])
			if err != nil {
				t.Fatal(err)
			}
		}
		plan.config.AuthorizeApplication = func(_ context.Context, request AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
			lease, err := request.ReserveLease(request.Binding(), nil, func(context.Context) error { return nil })
			if err == nil {
				err = lease.SetServiceAccess(policy.Namespace, policy.Type, true)
			}
			return AuthorizeApplicationResult{Lease: lease}, err
		}
		plan.claimed = true
		if err := plan.authorize(ctx, ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt, ApplicationProfile: "services"}, authorization.Check); err != nil {
			t.Fatal(err)
		}
		if err := plan.lease.bindAuthorization(authorization); err != nil {
			t.Fatal(err)
		}
		plan.services.activate()
		if len(unary) != 0 && unary[0] {
			host.mu.Lock()
			host.application = plan
			host.mu.Unlock()
			e := environments[role]
			e.mu.Lock()
			e.positions[0] = host
			e.mu.Unlock()
			e.signalMaterials()
			t.Cleanup(func() { e.mu.Lock(); e.positions[0] = nil; e.mu.Unlock(); e.signalMaterials() })
		}
		// Join this fixture's borrowed application owners before its trust
		// fixture destroys the namespace. Core/provider cleanup alone runs
		// later and cannot stand in for actual handler/subscription exit.
		t.Cleanup(func() {
			for _, core := range cores {
				core.Close()
			}
			plan.Close()
			r.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := r.waitCalls(cleanup); err != nil {
				t.Error(err)
			}
			if err := plan.releaseAfterCleanup(cleanup); err != nil {
				t.Error("application owners did not release their trust subscriptions", err)
			}
		})
		for {
			r.mu.Lock()
			started := r.runtimeStarted
			r.mu.Unlock()
			if started {
				break
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			runtime.Gosched()
		}
	}
}
