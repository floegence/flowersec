package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func coreBatchTestRoot(t *testing.T) (*resourcev4.Root, resourcev4.Reference, resourcev4.OwnerKey, SessionResourceScope) {
	t.Helper()
	limit := resourcev4.Vector{resourcev4.SDKBytes: 64 << 20, resourcev4.ProviderBytes: 1 << 20, resourcev4.Items: 4096,
		resourcev4.WorkSlots: 256, resourcev4.Tasks: 256, resourcev4.Timers: 256, resourcev4.Sessions: 2}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 256, ReferenceSlots: 512})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("original batch resources retained", root.Snapshot())
		}
	})
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	owner.Instance, owner.Backing, owner.Kind = [16]byte{2}, [16]byte{2}, 2
	return root, environment, owner, corePlanTestScope(t, root, limit, 1)
}

func TestSessionCoreBatchAggregateRollbackPreservesOriginalEnvironment(t *testing.T) {
	root, environment, owner, scope := coreBatchTestRoot(t)
	before := root.Snapshot()
	var batch sessionCoreBatch
	if err := prepareSessionCoreBatch(&batch, corePlanUnitConfig(t, false), root, owner, environment, scope); err != nil {
		t.Fatal(err)
	}
	defer batch.release()
	var requests [coreOwnerCapacity + 1]resourcev4.Request
	var refs [coreOwnerCapacity + 1]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		request, err := batch.request(i)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = request
	}
	core := requests[:batch.count]
	extra := owner
	extra.Backing = [16]byte{99}
	requests[len(core)] = resourcev4.Request{Owner: extra, Charge: resourcev4.Vector{resourcev4.SDKBytes: before.Limit[resourcev4.SDKBytes]}}
	prepared := root.Snapshot()
	if err := root.ReserveBatch(requests[:len(core)+1], refs[:len(core)+1]); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("aggregate shortage admitted core prefix", err)
	}
	if root.Snapshot() != prepared {
		t.Fatal("failed aggregate retained a partial core")
	}
	batch.release()
	if root.Snapshot() != before || environment.Check() != nil {
		t.Fatal("construction rollback consumed original Environment")
	}
}

func TestSessionCoreBatchAdoptsAtReferenceCapacityAndInvalidatesCopies(t *testing.T) {
	for _, messages := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "messages"}[messages], func(t *testing.T) {
			c := corePlanUnitConfig(t, false)
			c.MessageCarrier, c.MessageRuntimeBytes = messages, 65536
			original := c
			root, environment, owner, scope := coreBatchTestRoot(t)
			extraAccount, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.EnvironmentAccount, ID: owner.Environment}, root.Snapshot().Limit)
			if err != nil {
				t.Fatal(err)
			}
			accounts := []resourcev4.Account{extraAccount}
			var batch sessionCoreBatch
			if err := prepareSessionCoreBatch(&batch, c, root, owner, environment, scope, accounts...); err != nil {
				t.Fatal(err)
			}
			defer batch.release()
			borrowCopies := batch.borrows
			c.Open.Active, accounts[0] = 0, resourcev4.Account{}
			var requests [coreOwnerCapacity + 1]resourcev4.Request
			var refs [coreOwnerCapacity + 1]resourcev4.Reference
			for i := 0; i < batch.count; i++ {
				request, err := batch.request(i)
				if err != nil {
					t.Fatal(err)
				}
				requests[i] = request
			}
			core := requests[:batch.count]
			extra := owner
			extra.Backing = [16]byte{99}
			requests[len(core)] = resourcev4.Request{Owner: extra, Charge: resourcev4.Vector{resourcev4.Items: 1}, Accounts: batch.accounts[:batch.accountCount]}
			if err := root.ReserveBatch(requests[:len(core)+1], refs[:len(core)+1]); err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, ref := range refs {
					ref.Release()
				}
			}()
			var held []resourcev4.Reference
			for {
				ref, err := environment.Borrow()
				if errors.Is(err, resourcev4.ErrCapacity) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				held = append(held, ref)
			}
			defer func() {
				for _, ref := range held {
					ref.Release()
				}
			}()
			before := root.Snapshot()
			plan, err := batch.adopt(refs[:len(core)])
			if err != nil {
				t.Fatal("adoption required another reference", err)
			}
			cleanupCorePlanUnit(t, plan)
			for _, ref := range refs[:len(core)] {
				if !errors.Is(ref.Check(), resourcev4.ErrOwner) {
					t.Fatal("aggregate retained a live core alias")
				}
				ref.Release()
			}
			for _, ref := range borrowCopies {
				ref.Release()
			}
			batch.release()
			if root.Snapshot() != before || plan.CheckEnvironment(environment) != nil || refs[len(core)].Check() != nil {
				t.Fatal("adoption duplicated or released original ownership")
			}
			if plan.config.Open != original.Open || plan.accounts[2] != extraAccount {
				t.Fatal("adoption reread mutable config or account input")
			}
			if other, err := batch.adopt(refs[:len(core)]); other != nil || !errors.Is(err, resourcev4.ErrOwner) {
				t.Fatal("batch adopted twice", err)
			}
		})
	}
}

func TestSessionCoreBatchPartialAdoptionLeavesUntakenReferencesWithCaller(t *testing.T) {
	for _, malformed := range []string{"stale", "short", "undersized"} {
		t.Run(malformed, func(t *testing.T) {
			root, environment, owner, scope := coreBatchTestRoot(t)
			before := root.Snapshot()
			var batch sessionCoreBatch
			if err := prepareSessionCoreBatch(&batch, corePlanUnitConfig(t, false), root, owner, environment, scope); err != nil {
				t.Fatal(err)
			}
			defer batch.release()
			var requests [coreOwnerCapacity + 1]resourcev4.Request
			var refs [coreOwnerCapacity + 1]resourcev4.Reference
			for i := 0; i < batch.count; i++ {
				request, err := batch.request(i)
				if err != nil {
					t.Fatal(err)
				}
				requests[i] = request
			}
			core := requests[:batch.count]
			if malformed == "undersized" {
				requests[1].Charge[resourcev4.SDKBytes]--
			}
			extra := owner
			extra.Backing = [16]byte{99}
			requests[len(core)] = resourcev4.Request{Owner: extra, Charge: resourcev4.Vector{resourcev4.Items: 1}}
			if err := root.ReserveBatch(requests[:len(core)+1], refs[:len(core)+1]); err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, ref := range refs {
					ref.Release()
				}
			}()
			input := refs[:len(core)]
			if malformed == "stale" {
				refs[1].Release()
			} else if malformed == "short" {
				input = input[:len(input)-1]
			}
			if plan, err := batch.adopt(input); plan != nil || err == nil {
				t.Fatal("malformed core adopted", err)
			}
			if malformed != "short" && !errors.Is(refs[0].Check(), resourcev4.ErrOwner) {
				t.Fatal("failed adoption retained the already consumed prefix")
			}
			for _, ref := range refs[2 : len(core)+1] {
				if err := ref.Check(); err != nil {
					t.Fatal("failed adoption released caller-owned remainder", err)
				}
			}
			for _, ref := range refs {
				ref.Release()
			}
			if root.Snapshot() != before || environment.Check() != nil {
				t.Fatal("caller rollback left partial core ownership")
			}
		})
	}
}

func TestSessionCoreBatchClaimsHandlersOnlyAfterReferenceAdoption(t *testing.T) {
	root, environment, owner, scope := coreBatchTestRoot(t)
	executorConfig := ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
	executorCharge, err := ApplicationExecutorCharge(executorConfig)
	if err != nil {
		t.Fatal(err)
	}
	reserve := func(id byte, charge resourcev4.Vector) resourcev4.Reference {
		t.Helper()
		key := owner
		key.Backing = [16]byte{id}
		ref, err := root.Reserve(key, charge)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	executor, err := NewApplicationExecutor(executorConfig, reserve(90, executorCharge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.Close(); <-executor.Done() })
	handlerConfig := streamHandlerTestConfig()
	handlerCharge, err := StreamHandlerPlanCharge(handlerConfig)
	if err != nil {
		t.Fatal(err)
	}
	delegates, err := environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer delegates.Release()
	handlers, err := NewStreamHandlerPlan(handlerConfig, executor, reserve(91, handlerCharge), delegates)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreamHandlerPlan(t, handlers)
	c := corePlanUnitConfig(t, false)
	c.Streams = factoryStreamConfig()
	c.Handlers = SessionStreamHandlerConfig{Plan: handlers, Concurrency: 1, TimeoutMS: 1000, RuntimeBytes: 4096, RuntimeBytesPerInvocation: 4096}
	before := root.Snapshot()
	var batch sessionCoreBatch
	if err := prepareSessionCoreBatch(&batch, c, root, owner, environment, scope); err != nil {
		t.Fatal(err)
	}
	defer batch.release()
	var requests [coreOwnerCapacity]resourcev4.Request
	var refs [coreOwnerCapacity]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		request, err := batch.request(i)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = request
	}
	core := requests[:batch.count]
	if err := root.ReserveBatch(core, refs[:len(core)]); err != nil {
		t.Fatal(err)
	}
	refs[1].Release()
	if plan, err := batch.adopt(refs[:len(core)]); plan != nil || err == nil {
		t.Fatal("stale core adopted")
	}
	for _, ref := range refs {
		ref.Release()
	}
	if root.Snapshot() != before || handlers.claimed {
		t.Fatal("failed reference adoption claimed or retained handler resources")
	}
	plan, err := NewSessionCorePlan(c, root, owner, environment, scope)
	if err != nil {
		t.Fatal("original handler plan no longer available", err)
	}
	cleanupCorePlanUnit(t, plan)
	if !handlers.claimed {
		t.Fatal("complete core omitted original handler claim")
	}
	before = root.Snapshot()
	otherScope := corePlanTestScope(t, root, before.Limit, 2)
	otherOwner := owner
	otherOwner.Backing = [16]byte{3}
	if other, err := NewSessionCorePlan(c, root, otherOwner, environment, otherScope); other != nil || !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("handler plan claimed twice", err)
	}
	if root.Snapshot() != before || handlers.closed {
		t.Fatal("duplicate handler claim damaged the original core")
	}
	if err := plan.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
}
