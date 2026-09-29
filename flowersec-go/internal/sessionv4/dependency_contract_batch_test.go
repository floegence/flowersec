package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func TestRequiredRemoteDependenciesBatchOnlyDeclaredInitialMethods(t *testing.T) {
	x := newRemoteServiceFixture(t, 12)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, InitialMethods: []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := x.plan.lease.SetContractQueryAccess(ContractQueryMethod{Namespace: x.definition.Namespace, Type: 5}, rpcv4.QueryTargetDenied); err != nil {
		t.Fatal(err)
	}
	methods := make([]ServiceDependencyMethod, 0, 11)
	for typeID := uint32(2); typeID <= 12; typeID++ {
		selection := ServiceDependencyMethod{Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: typeID}}
		if typeID >= 11 {
			selection.DispatchRequirement = OnUse
		}
		methods = append(methods, selection)
	}
	services := invocationDeclarations(t, x.executorFixture, []ServiceDependency{{Alias: "files", Client: client, Methods: methods}})
	ctx := resultTestContext(t)
	x.run(t, func() {
		for {
			client.mu.Lock()
			finished := true
			for i := 1; i < 10; i++ {
				finished = finished && (client.methods[i].installed || client.methods[i].dependencyPath.failure != nil)
			}
			client.mu.Unlock()
			x.environment.mu.Lock()
			finished = finished && !x.environment.dependencyContracts.batch.active
			x.environment.mu.Unlock()
			if finished || ctx.Err() != nil {
				return
			}
			runtime.Gosched()
		}
	})
	if ctx.Err() != nil {
		t.Fatal("required batch did not finish", ctx.Err())
	}
	for typeID := uint32(2); typeID <= 12; typeID++ {
		snapshot := client.Contract(typeID)
		if snapshot.Installed != (typeID != 5 && typeID < 11) {
			t.Fatal("changed unselected or independently denied snapshot", typeID, snapshot)
		}
	}
	client.mu.Lock()
	failure := client.methods[4].dependencyPath.failure
	client.mu.Unlock()
	if !errors.Is(failure, ErrContractDenied) || !errors.Is(services.requiredReady(context.Background()), cryptov4.ErrNotReady) {
		t.Fatal("denial lost its local dependency failure", failure)
	}
	if x.batches != 3 || len(x.deadlines) != 3 || x.deadlines[1] != x.deadlines[2] {
		t.Fatal("initial dependency batches changed target bounds or deadline", x.batches, x.deadlines)
	}
}

func TestRequiredRemoteDependencyCloseRejectsLateSnapshot(t *testing.T) {
	x := newRemoteServiceFixture(t, 2)
	var client *UnaryServiceClient
	var err error
	x.run(t, func() {
		client, err = x.session.BindMethods(context.Background(), x.definition, UnaryServiceBindOptions{ContractSource: ServiceContractsRemote, InitialMethods: []UnaryMethodSelector{{Namespace: x.definition.Namespace, Type: 1}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	services := invocationDeclarations(t, x.executorFixture, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: x.definition.Namespace, Type: 2}}}}})
	ctx := resultTestContext(t)
	for {
		client.mu.Lock()
		started := client.methods[1].update.query != nil
		client.mu.Unlock()
		if started {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("required query did not start", ctx.Err())
		}
		runtime.Gosched()
	}
	services.close()
	x.run(t, func() {
		for {
			x.environment.mu.Lock()
			active := x.environment.dependencyContracts.batch.active
			x.environment.mu.Unlock()
			if !active || ctx.Err() != nil {
				return
			}
			runtime.Gosched()
		}
	})
	if ctx.Err() != nil {
		t.Fatal("required query retained cleanup", ctx.Err())
	}
	if client.Contract(2).Installed || !client.Contract(1).Installed {
		t.Fatal("closed declaration installed late output or revoked independent snapshot")
	}
}
