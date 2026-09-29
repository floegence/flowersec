package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func invocationDeclarations(t *testing.T, f *executorFixture, declarations []ServiceDependency) *invocationServices {
	t.Helper()
	charge, err := serviceDependenciesCharge(declarations)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newInvocationServices(declarations, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return s
}

func TestInvocationDeclarationsSeparateRequiredAndOnUse(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	var encoded atomic.Int32
	for i := range definition.Methods {
		definition.Methods[i].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(context.Context, []byte, []byte) ([]byte, error) { encoded.Add(1); return []byte("input"), nil }}
	}
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	declarations := []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{
		{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}},
		{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 2}, DispatchRequirement: OnUse},
		{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 3}, DispatchRequirement: OnUse},
	}}}
	services := invocationDeclarations(t, f.f, declarations)
	if err := services.requiredReady(context.Background()); err != nil {
		t.Fatal("optional descriptor blocked required readiness", err)
	}
	// Registration is immutable even when the caller reuses its input slices.
	declarations[0].Alias = "changed"
	declarations[0].Methods[0].Method.Type = 3
	var saved InvocationService
	var savedContext context.Context
	runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
		if err := attachInvocationServices(ctx, services); err != nil {
			t.Fatal(err)
		}
		view, err := InvocationServiceFromContext(ctx, "files")
		if err != nil {
			t.Fatal(err)
		}
		saved, savedContext = view, ctx
		if _, err := InvocationServiceFromContext(ctx, "changed"); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal(err)
		}
		before := f.f.root.Snapshot()
		if op, err := view.Stream(ctx, UnaryMethodSelector{Namespace: definition.Namespace, Type: 2}, nil, synchronousOptions()); op != nil || !errors.Is(err, cryptov4.ErrNotReady) {
			t.Fatal(op, err)
		}
		if _, err := view.Notify(ctx, UnaryMethodSelector{Namespace: definition.Namespace, Type: 3}, nil, synchronousOptions()); !errors.Is(err, cryptov4.ErrNotReady) {
			t.Fatal(err)
		}
		if encoded.Load() != 0 || f.f.root.Snapshot() != before {
			t.Fatal("optional call created hidden preparation", encoded.Load())
		}
		if op, err := view.Prepare(ctx, UnaryMethodSelector{Namespace: "other", Type: 1}, nil, synchronousOptions()); op != nil || !errors.Is(err, rpcv4.ErrMethod) {
			t.Fatal(op, err)
		}
		if op, err := view.Prepare(context.Background(), UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}, nil, synchronousOptions()); op != nil || !errors.Is(err, ErrApplicationDependency) {
			t.Fatal(op, err)
		}
		op, err := view.Prepare(ctx, UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}, nil, synchronousOptions())
		if err != nil {
			t.Fatal(err)
		}
		defer op.Close()
		if op.header.Fields().AdmissionMode != 1 || encoded.Load() != 1 {
			t.Fatal("view changed original admission or codec ownership")
		}
	})
	if _, err := saved.Prepare(savedContext, UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}, nil, synchronousOptions()); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal("escaped invocation remained usable", err)
	}
	if len(f.sink.wire) != 0 {
		t.Fatal("declaration or readiness published hidden network work")
	}
}

func TestInvocationDeclarationsValidateAndReleaseOriginalBacking(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	valid := ServiceDependency{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}}}}
	for _, declarations := range [][]ServiceDependency{
		{{Alias: "", Client: client, Methods: valid.Methods}},
		{valid, valid},
		{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: valid.Methods[0].Method, DispatchRequirement: 2}}}},
		{{Alias: "files", Client: client, Methods: append(append([]ServiceDependencyMethod{}, valid.Methods...), valid.Methods...)}},
	} {
		if _, err := serviceDependenciesCharge(declarations); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal(err)
		}
	}
	declarations := []ServiceDependency{valid}
	charge, _ := serviceDependenciesCharge(declarations)
	backing := f.f.reserve(t, 1, charge)
	before := f.f.root.Snapshot()
	s, err := newInvocationServices(declarations, backing)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				_ = s.requiredReady(context.Background())
			}
		}()
	}
	s.close()
	wg.Wait()
	if got := f.f.root.Snapshot(); got != before {
		t.Fatal("closed declaration retained client/backing references", before, got)
	}
	if err := s.requiredReady(context.Background()); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal(err)
	}
	if err := client.SelectMethod(valid.Methods[0].Method); err != nil {
		t.Fatal("closing declaration closed borrowed service", err)
	}
}

func TestInvocationRequiredStreamUnionCapacity(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	// Build three original method slots in the fixture's charged method table.
	client.mu.Lock()
	for i := range client.methods {
		client.methods[i].definition.Shape = 1
	}
	client.mu.Unlock()
	methods := []ServiceDependencyMethod{}
	for _, method := range definition.Methods {
		methods = append(methods, ServiceDependencyMethod{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: method.Type}})
	}
	declarations := []ServiceDependency{{Alias: "files", Client: client, Methods: methods}}
	charge, _ := serviceDependenciesCharge(declarations)
	backing := f.f.reserve(t, 1, charge)
	before := f.f.root.Snapshot()
	if s, err := newInvocationServices(declarations, backing); s != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(s, err)
	}
	if f.f.root.Snapshot() != before {
		t.Fatal("failed union leaked reference")
	}
	methods[2].DispatchRequirement = OnUse
	s, err := newInvocationServices(declarations, backing)
	if err != nil {
		t.Fatal("optional stream counted as simultaneous pool demand", err)
	}
	s.close()
}

func TestInvocationRequiredStreamCapacityAcrossRegistrations(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	var clients [3]*UnaryServiceClient
	for i := range clients {
		client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
		t.Cleanup(client.Close)
		client.mu.Lock()
		for j := range client.methods {
			client.methods[j].definition.Shape = 1
		}
		client.mu.Unlock()
	}
	declaration := func(client *UnaryServiceClient, typeID uint32) []ServiceDependency {
		return []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: typeID}}}}}
	}
	first := invocationDeclarations(t, f.f, declaration(clients[0], 1))
	second := invocationDeclarations(t, f.f, declaration(clients[1], 2))
	shared := invocationDeclarations(t, f.f, declaration(clients[2], 1))
	before := clients[2].Contract(1)
	if _, err := clients[2].UpdateContract(context.Background(), 1, [32]byte{231}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("contract update split a shared target beyond the service pool", err)
	}
	if after := clients[2].Contract(1); after.Digest != before.Digest || after.Generation != before.Generation {
		t.Fatal("failed capacity qualification changed the original contract", before, after)
	}
	third := declaration(clients[2], 3)
	charge, _ := serviceDependenciesCharge(third)
	backing := f.f.reserve(t, 1, charge)
	if s, err := newInvocationServices(third, backing); s != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("separate registrations exceeded the shared service pool", err)
	}
	first.close()
	if s, err := newInvocationServices(third, backing); s != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("closing one declaration removed a shared target", err)
	}
	shared.close()
	s, err := newInvocationServices(third, backing)
	if err != nil {
		t.Fatal("closed target retained future demand", err)
	}
	s.close()
	second.close()
}

func TestInvocationRequiredStaticDescriptorsInstallWithoutOptionalWork(t *testing.T) {
	f, r, _, definition, _ := serviceMethodsFixture(t, 3)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	services := invocationDeclarations(t, f.f, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{
		{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 2}},
		{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 3}, DispatchRequirement: OnUse},
	}}})
	deadline := time.Now().Add(3 * time.Second)
	for services.requiredReady(context.Background()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("required static descriptor was not prepared")
		}
		runtime.Gosched()
	}
	if !client.Contract(2).Installed || client.Contract(3).Installed {
		t.Fatal("required installation changed optional snapshot selection")
	}
	if len(f.sink.wire) != 0 {
		t.Fatal("static installation started hidden network work")
	}
}

func TestInvocationRequiredStreamCapacityCombinesFixedAndControllerSources(t *testing.T) {
	f, r, e, definition := serviceShapesFixture(t)
	var clients [3]*UnaryServiceClient
	for i := range clients {
		client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
		t.Cleanup(client.Close)
		client.mu.Lock()
		for j := range client.methods {
			client.methods[j].definition.Shape = 1
		}
		client.mu.Unlock()
	}
	session := &EnvironmentSession{core: &SessionCore{plan: &SessionCorePlan{rpc: r}}}
	controller := &ConnectionController{environment: e, current: session}
	clients[1].mu.Lock()
	clients[1].source.controller = controller
	clients[1].services = nil
	clients[1].mu.Unlock()
	declaration := func(client *UnaryServiceClient, typeID uint32) []ServiceDependency {
		return []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: typeID}}}}}
	}
	invocationDeclarations(t, f.f, declaration(clients[0], 1))
	invocationDeclarations(t, f.f, declaration(clients[1], 1))
	invocationDeclarations(t, f.f, declaration(clients[1], 2))
	third := declaration(clients[2], 3)
	charge, _ := serviceDependenciesCharge(third)
	backing := f.f.reserve(t, 1, charge)
	if s, err := newInvocationServices(third, backing); s != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("fixed and Controller declarations overcommitted their shared Session", err)
	}
	// The other physical source has independent pool capacity. Its logical
	// Controller target still owns exactly the same required method slots.
	controller.mu.Lock()
	controller.current = &EnvironmentSession{core: &SessionCore{plan: &SessionCorePlan{rpc: &RPCServices{}}}}
	controller.mu.Unlock()
	s, err := newInvocationServices(third, backing)
	if err != nil {
		t.Fatal("separate Session capacity was combined", err)
	}
	s.close()
}

func TestInvocationNotificationConstructionReleasesAuthorityGates(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	n := newNotificationFixture(t)
	client.mu.Lock()
	locked := true
	defer func() {
		if locked {
			client.mu.Unlock()
		}
	}()
	result := make(chan error, 1)
	go func() {
		_, err := n.d.Subscribe(0, NotificationDropNewest, NotificationObserver{
			Dependencies: []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}, DispatchRequirement: OnUse}}}},
			Decode:       func(context.Context, []byte) (any, error) { return nil, nil }, Handle: func(context.Context, any) error { return nil },
		})
		result <- err
	}()
	// Observe the actually reserved construction slot while client metadata is
	// held. The dispatcher must remain available for Close and authorization.
	deadline := time.After(3 * time.Second)
	for {
		n.d.mu.Lock()
		reserved := false
		for _, token := range n.d.tokens {
			reserved = reserved || token != nil && token.preparing
		}
		n.d.mu.Unlock()
		if reserved {
			break
		}
		select {
		case err := <-result:
			t.Fatal("client contention rejected registration", err)
		case <-deadline:
			t.Fatal("registration did not release the dispatcher gate")
		default:
		}
	}
	n.d.Close()
	client.mu.Unlock()
	locked = false
	select {
	case err := <-result:
		if !errors.Is(err, rpcv4.ErrClosed) {
			t.Fatal("late registration escaped Close", err)
		}
	case <-deadline:
		t.Fatal("closed registration retained its construction slot")
	}
}

func TestInvocationRequiredRejectsBeforeUnaryHandler(t *testing.T) {
	for _, mode := range []uint8{0, 1} {
		t.Run([]string{"queued", "try_now"}[mode], func(t *testing.T) {
			f, r, _, definition := serviceShapesFixture(t)
			client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			var calls atomic.Int32
			services := invocationDeclarations(t, f.f, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 2}}}}})
			f.dispatch.mu.Lock()
			f.dispatch.methods[0].registration.services = services
			f.dispatch.methods[0].registration.Handler = func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { calls.Add(1); return 0, nil }
			f.dispatch.mu.Unlock()
			before := f.f.executor.Snapshot()
			f.request(t, []byte("input"), mode, 2000)
			if err := f.dispatch.Admit(f.receiver, f.publisher); !errors.Is(err, cryptov4.ErrNotReady) {
				t.Fatal(err)
			}
			header, _ := f.response(t)
			if !header.IsSDKError() || calls.Load() != 0 {
				t.Fatal(header.Kind(), calls.Load())
			}
			if got := f.f.executor.Snapshot(); got.Running != before.Running || got.Ready != before.Ready {
				t.Fatal("missing dependency took ordinary capacity", before, got)
			}
		})
	}
}

func TestInvocationDeclarationCloseSealsOriginalPreparedStart(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	selector := UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}
	services := invocationDeclarations(t, f.f, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: selector}}}})
	runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
		if err := attachInvocationServices(ctx, services); err != nil {
			t.Fatal(err)
		}
		view, err := InvocationServiceFromContext(ctx, "files")
		if err != nil {
			t.Fatal(err)
		}
		op, err := view.Prepare(ctx, selector, nil, synchronousOptions())
		if err != nil {
			t.Fatal(err)
		}
		defer op.Close()
		services.close()
		if start := op.Start(context.Background()); !start.NotAdmitted || !errors.Is(start.Error, ErrApplicationDependency) {
			t.Fatal("closed declaration accepted new child", start)
		}
		if _, err := view.Prepare(ctx, selector, nil, synchronousOptions()); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal(err)
		}
		if _, err := InvocationServiceFromContext(ctx, "files"); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal(err)
		}
	})
	if err := client.SelectMethod(selector); err != nil {
		t.Fatal("declaration closed borrowed client", err)
	}
}

func TestInvocationNotificationDependencyWaitsOutsideOrdinaryQueue(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	n := newNotificationFixture(t)
	var requiredCalls, optionalCalls atomic.Int32
	dependency := ServiceDependency{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 3}}}}
	required := n.subscribe(t, NotificationDropNewest, NotificationObserver{Dependencies: []ServiceDependency{dependency}, Decode: func(context.Context, []byte) (any, error) { requiredCalls.Add(1); return nil, nil }, Handle: func(context.Context, any) error { return nil }})
	dependency.Methods = []ServiceDependencyMethod{{Method: dependency.Methods[0].Method, DispatchRequirement: OnUse}}
	n.subscribe(t, NotificationDropNewest, NotificationObserver{Dependencies: []ServiceDependency{dependency}, Decode: func(ctx context.Context, _ []byte) (any, error) {
		if _, err := InvocationServiceFromContext(ctx, "files"); err != nil {
			t.Error(err)
		}
		optionalCalls.Add(1)
		return nil, nil
	}, Handle: func(context.Context, any) error { return nil }})
	n.send(t, "notice")
	n.until(t, func() bool { return optionalCalls.Load() == 1 })
	n.d.Advance()
	if requiredCalls.Load() != 0 || required.Status().Pending != 1 || required.Status().Running != 0 {
		t.Fatal(requiredCalls.Load(), required.Status())
	}
	n.d.mu.Lock()
	queued := required.token.jobs[0].queued
	n.d.mu.Unlock()
	if queued != nil {
		t.Fatal("unready required notification occupied ordinary ready capacity")
	}
}
