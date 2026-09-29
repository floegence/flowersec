package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func serviceMethodsFixture(t *testing.T, count int) (*serviceDispatchFixture, *RPCServices, *Environment, UnaryServiceDefinition, [3][32]byte) {
	t.Helper()
	f, r, _, e := deferredCallerFixture(t)
	body := initialFixture(t, "service_unary_transient")
	cfg := rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 4096, Methods: make([]rpcv4.MethodRoutes, count)}
	definition := UnaryServiceDefinition{Namespace: f.policy.Namespace, Methods: make([]UnaryServiceMethod, count)}
	var variants [3][32]byte
	for j := range cfg.Methods {
		wire := admissionMap(t, "ServiceContract", body, map[string]protocolv4.Field{"type_id": {Number: uint64(j + 1)}})
		codec, _ := protocolv4.NewServiceContractCodec(256)
		contract, err := codec.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := contract.Digest()
		contract.Release()
		cfg.Methods[j].Contracts = [][]byte{wire}
		definition.Methods[j] = UnaryServiceMethod{Type: uint32(j + 1), Method: UnaryMethodDefinition{Contract: digest, WorkClass: ApplicationShort, DefaultResponseLimitBytes: 1024, Decode: synchronousResult}}
		if j == 0 {
			for k, changes := range []map[string]protocolv4.Field{
				{"max_response_bytes": {Number: 2048}},
				{"min_response_limit_bytes": {Number: 2048}, "max_response_bytes": {Number: 4096}},
				{"request_max_bytes": {Number: 777}},
			} {
				variant := admissionMap(t, "ServiceContract", wire, changes)
				contract, err := codec.Decode(variant)
				if err != nil {
					t.Fatal(err)
				}
				variants[k], _ = contract.Digest()
				contract.Release()
				cfg.Methods[j].Contracts = append(cfg.Methods[j].Contracts, variant)
			}
		}
	}
	charge, err := rpcv4.ContractRoutesCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(cfg, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	r.routes = routes
	return f, r, e, definition, variants
}

func TestServiceClientMethodsPartialInstallAndIndependentRefresh(t *testing.T) {
	_, r, e, definition, variants := serviceMethodsFixture(t, 3)
	var encodes atomic.Int32
	definition.Methods[1].Method.Codec = SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(_ context.Context, input, _ []byte) ([]byte, error) { encodes.Add(1); return input, nil }}
	client, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := client.SelectMethod(UnaryMethodSelector{Namespace: "other.service", Type: 1}); err != rpcv4.ErrMethod {
		t.Fatal("cross-service selector accepted", err)
	}
	if e.OperationsSnapshot().BoundMethods != 3 {
		t.Fatal("uninstalled descriptors escaped aggregate accounting")
	}
	if s := client.Contract(2); s.Installed || s.Digest != ([32]byte{}) || s.Error != cryptov4.ErrNotReady {
		t.Fatal(s)
	}
	if op, err := client.PrepareMethod(context.Background(), 2, nil, rpcv4.UnaryPreparation{}); op != nil || err != cryptov4.ErrNotReady || encodes.Load() != 0 {
		t.Fatal("uninstalled method entered encoder", err)
	}
	if _, err := client.UpdateContract(context.Background(), 2, variants[0]); err != cryptov4.ErrNotReady {
		t.Fatal(err)
	}
	if err := r.routes.SetRegistered(definition.Methods[2].Method.Contract, false); err != nil {
		t.Fatal(err)
	}
	var statuses [2]UnaryContractSnapshot
	if err := client.Refresh(context.Background(), []uint32{2, 3}, statuses[:]); err != nil {
		t.Fatal(err)
	}
	if !statuses[0].Installed || statuses[0].Error != nil || statuses[1].Installed || statuses[1].Error == nil {
		t.Fatal(statuses)
	}
	if !client.Contract(1).Installed {
		t.Fatal("partial failure removed independent snapshot")
	}
	if err := client.Refresh(context.Background(), []uint32{2, 2}, statuses[:]); err == nil {
		t.Fatal("duplicate selector admitted")
	}
	if _, err := client.Prepare(context.Background(), nil, rpcv4.UnaryPreparation{}); err != rpcv4.ErrMethod {
		t.Fatal("ambiguous no-selector call", err)
	}
	definition.Methods[1].Method.Contract = [32]byte{99}
	op, err := client.PrepareMethod(context.Background(), 2, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
	if err != nil {
		t.Fatal(err)
	}
	op.Close()
	if encodes.Load() != 1 {
		t.Fatal("wrong codec dispatch")
	}
	client.Close()
	e.advanceServiceClients()
	if e.OperationsSnapshot().BoundMethods != 0 {
		t.Fatal("clean binding retained method slots")
	}
}

func TestServiceClientMethodsUpdatePreservesPreparedAndDefault(t *testing.T) {
	_, r, _, definition, variants := serviceMethodsFixture(t, 2)
	client, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	prepare := func() *UnaryOperation {
		op, err := client.PrepareMethod(context.Background(), 1, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(op.Close)
		return op
	}
	old := prepare()
	s, err := client.UpdateContract(context.Background(), 1, variants[0])
	if err != nil || s.Digest != variants[0] || s.Generation != 2 {
		t.Fatal(s, err)
	}
	next := prepare()
	if old.header.Fields().ServiceContractDigest != definition.Methods[0].Method.Contract || next.header.Fields().ServiceContractDigest != variants[0] || next.header.Fields().ResponseLimitBytes != 1024 {
		t.Fatal("update rewrote original capture or default")
	}
	if _, err := client.UpdateContract(context.Background(), 1, variants[1]); !errors.Is(err, rpcv4.ErrResponseLimitUnsupported) {
		t.Fatal("invalid default accepted", err)
	}
	if client.Contract(1).Digest != variants[0] || client.Contract(2).Digest != definition.Methods[1].Method.Contract {
		t.Fatal("failed update changed snapshot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.UpdateContract(ctx, 1, variants[2]); err != context.Canceled {
		t.Fatal(err)
	}
	client.Close()
	if _, err := client.UpdateContract(context.Background(), 1, variants[2]); err != cryptov4.ErrClosed {
		t.Fatal(err)
	}
}

func TestServiceClientMethodsBoundedUpdateChecksCanonicalPolicy(t *testing.T) {
	_, r, _, definition, variants := serviceMethodsFixture(t, 1)
	definition.Methods[0].Acceptance, _ = protocolv4.BoundedContractAcceptance(protocolv4.ContractRange{Field: "max_response_bytes", Lower: 1024, Upper: 1048576})
	client, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := client.UpdateContract(context.Background(), 1, variants[2]); err != protocolv4.ErrContractPolicyRejected {
		t.Fatal("unlisted request bound changed", err)
	}
	if _, err := client.UpdateContract(context.Background(), 1, variants[0]); err != nil {
		t.Fatal(err)
	}
	if client.Contract(1).Acceptance != protocolv4.ContractBounded {
		t.Fatal("policy replaced by explicit digest approval")
	}
}

func TestServiceClientMethodsAggregateAndInitialSelectionLimits(t *testing.T) {
	_, r, e, definition, _ := serviceMethodsFixture(t, 16)
	e.mu.Lock()
	e.maxBoundMethods = 16
	e.mu.Unlock()
	for _, initial := range [][]uint32{{}, {1, 1}, {99}} {
		if c, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: func() []UnaryMethodSelector {
			selected := make([]UnaryMethodSelector, len(initial))
			for j, id := range initial {
				selected[j] = UnaryMethodSelector{Namespace: definition.Namespace, Type: id}
			}
			return selected
		}()}); err == nil || c != nil {
			t.Fatal("invalid initial selection admitted", initial)
		}
	}
	client, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if extra, err := r.bindUnaryService(definition.Methods[0].Method); err != cryptov4.ErrCapacity || extra != nil {
		t.Fatal("aggregate descriptor overflow", err)
	}
	client.Close()
	e.advanceServiceClients()
	if e.OperationsSnapshot().BoundMethods != 0 {
		t.Fatal("descriptor slots leaked")
	}
	replacement, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{InitialMethods: []UnaryMethodSelector{{Namespace: definition.Namespace, Type: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replacement.Close)
}

func TestServiceClientUnpublishedBindCountsUntilActualExit(t *testing.T) {
	f, r, e, definition, _ := serviceMethodsFixture(t, 2)
	e.mu.Lock()
	e.maxBoundMethods = 2
	e.mu.Unlock()
	lease, _, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	lease.mu.Lock()
	locked := true
	defer func() {
		if locked {
			lease.mu.Unlock()
		}
	}()
	ctx, cancel := context.WithCancel(resultTestContext(t))
	defer cancel()
	done := make(chan error, 1)
	go func() {
		client, err := r.bindMethods(ctx, definition, UnaryServiceBindOptions{})
		if client != nil {
			client.Close()
			err = errors.New("canceled Bind delivered")
		}
		done <- err
	}()
	for e.OperationsSnapshot().ActiveServiceClients == 0 {
		if ctx.Err() != nil {
			t.Fatal("Bind did not own its finite index")
		}
		runtime.Gosched()
	}
	if s := e.OperationsSnapshot(); s.BoundMethods != 2 {
		t.Fatal(s)
	}
	if index, err := e.reserveServiceBinding(1); index != -1 || err != cryptov4.ErrCapacity {
		t.Fatal("unpublished methods bypassed capacity", index, err)
	}
	cancel()
	if s := e.OperationsSnapshot(); s.ActiveServiceClients != 1 || s.BoundMethods != 2 {
		t.Fatal("cancellation erased blocked owner", s)
	}
	lease.mu.Unlock()
	locked = false
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s := e.OperationsSnapshot(); s.ActiveServiceClients != 0 || s.BoundMethods != 0 {
		t.Fatal("failed Bind leaked original index", s)
	}
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal("actual cleanup did not return capacity", err)
	}
	t.Cleanup(client.Close)
}

func TestServiceClientMethodsUpdateJoinConflictAndCloseFence(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "install", true: "close"}[closeFirst], func(t *testing.T) {
			f, r, _, definition, variants := serviceMethodsFixture(t, 1)
			client, err := r.bindUnaryMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			ctx := resultTestContext(t)
			lease, _, err := f.plan.queryAuthorization()
			if err != nil {
				t.Fatal(err)
			}
			lease.mu.Lock()
			locked := true
			defer func() {
				if locked {
					lease.mu.Unlock()
				}
			}()
			finished := make(chan error, 1)
			go func() { _, err := client.UpdateContract(ctx, 1, variants[0]); finished <- err }()
			for {
				client.mu.Lock()
				active := client.methods[0].update.active
				client.mu.Unlock()
				if active {
					break
				}
				if ctx.Err() != nil {
					t.Fatal("update did not reserve original slot")
				}
				runtime.Gosched()
			}
			if _, err := client.UpdateContract(ctx, 1, variants[2]); err != ErrContractUpdateInProgress {
				t.Fatal("conflicting target waited or replaced owner", err)
			}
			if s := client.Contract(1); !s.Updating || s.PendingDigest != variants[0] || s.Digest != definition.Methods[0].Method.Contract {
				t.Fatal("pending target presented as installed", s)
			}
			observer, cancel := context.WithCancel(ctx)
			joined := make(chan error, 1)
			go func() { _, err := client.UpdateContract(observer, 1, variants[0]); joined <- err }()
			for {
				client.mu.Lock()
				waiters := client.methods[0].update.waiters
				client.mu.Unlock()
				if waiters == 1 {
					break
				}
				if ctx.Err() != nil {
					t.Fatal("same target did not join")
				}
				runtime.Gosched()
			}
			cancel()
			if err := <-joined; err != context.Canceled {
				t.Fatal("observer cancellation changed owner", err)
			}
			if closeFirst {
				client.Close()
			}
			lease.mu.Unlock()
			locked = false
			err = <-finished
			if closeFirst {
				if err != cryptov4.ErrClosed {
					t.Fatal("late update escaped Close", err)
				}
			} else if err != nil || client.Contract(1).Digest != variants[0] {
				t.Fatal("observer canceled original update", err)
			}
		})
	}
}
