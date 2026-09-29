package rpcv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type issuanceContinuity struct {
	identity ledgerv4.SQLiteIdentity
	service  ledgerv4.SQLiteExecutionService
}

func (c issuanceContinuity) CheckExecutionHistory(i ledgerv4.SQLiteIdentity, s ledgerv4.SQLiteExecutionService, _ uint64, _ bool) error {
	if i != c.identity || s != c.service {
		return ledgerv4.ErrFenced
	}
	return nil
}

func TestCheckpointIssuancePersistsOriginalUnaryResultAcrossDuplicateAndReopen(t *testing.T) {
	ctx := context.Background()
	clock := executionClock(t)
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 64, ReferenceSlots: 128}
	for i := range config.Limit {
		config.Limit[i] = 1 << 32
	}
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("issuance leaked backing", root.Snapshot())
		}
	})
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	reserve := func(cost resourcev4.Vector) resourcev4.Reference {
		owner.Instance[0]++
		owner.Backing[0]++
		ref, err := root.Reserve(owner, cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	environment := reserve(resourcev4.Vector{resourcev4.Items: 1})
	_, contract, _ := inputFixture(t, true, nil)
	var fixture [8192]byte
	fixtureSize, err := contract.CopyCanonical(fixture[:])
	if err != nil {
		t.Fatal(err)
	}
	contract.Release()
	if fixture[0] != 0xb3 || bytes.Count(fixture[:fixtureSize], []byte{0x15, 0xf4}) != 1 {
		t.Fatal("checkpoint contract fixture changed")
	}
	// Register explicit checkpoint semantics in this trusted test method.
	checkpointContract := bytes.Replace(fixture[:fixtureSize], []byte{0x15, 0xf4}, append([]byte{0x14, 0x66}, append([]byte("offset"), 0x15, 0xf4)...), 1)
	checkpointContract[0]++
	contractCodec, _ := protocolv4.NewServiceContractCodec(512)
	contract, err = contractCodec.Decode(checkpointContract)
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	policy, _ := contract.Policy()
	shape, _ := contract.MethodShapeDigest()
	var contractBytes [8192]byte
	n, err := contract.CopyCanonical(contractBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	rc := ContractRoutesConfig{Methods: []MethodRoutes{{Contracts: [][]byte{contractBytes[:n]}}}, ContractNodes: 512, RuntimeBytes: 4096, Clock: clock}
	cost, err := ContractRoutesCharge(rc)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewContractRoutes(rc, reserve(cost))
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	limits := ledgerv4.SQLiteLimits{MaxPages: 1024, MaxRecords: 2, MaxRecordBytes: 1 << 20, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	path := filepath.Join(t.TempDir(), "issuance.db")
	cost, _ = ledgerv4.SQLiteBackingCharge(limits)
	backing, err := ledgerv4.NewSQLiteBacking(path, limits, reserve(cost), environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	service := ExecutionService{"tenant", "audience", policy.Namespace}
	dbService := ledgerv4.SQLiteExecutionService{Tenant: service.Tenant, Audience: service.Audience, Namespace: service.Namespace}
	identity := ledgerv4.SQLiteIdentity{Authority: "issuance.test", StoreID: [32]byte{3}, Generation: 1}
	dbc := ledgerv4.SQLiteExecutionConfig{Root: root, Owner: owner, Clock: clock, Service: dbService, CallerAuthorities: [][32]byte{{8}}, Methods: []ledgerv4.SQLiteExecutionMethod{{Type: policy.Type, Shape: shape}}, Active: 2, ContractNodes: 512, WorkRuntimeBytes: 4096, RecoveryTokensPerOperation: 2, RecoveryMaxIssuedDurationMS: 1000}
	var store *ledgerv4.SQLiteExecutions
	var history *DurableExecutions
	open := func(create bool) {
		cost, err := ledgerv4.SQLiteExecutionsCharge(limits, dbc)
		if err != nil {
			t.Fatal(err)
		}
		method := ledgerv4.OpenSQLiteExecutions
		if create {
			method = ledgerv4.CreateSQLiteExecutions
		}
		store, err = method(ctx, backing, identity, issuanceContinuity{identity, dbService}, dbc, reserve(cost), environment)
		if err != nil {
			t.Fatal(err)
		}
		if create {
			if _, err = store.InstallContract(ctx, 0, contractBytes[:n], []timev4.Interval{{LowerMS: 0, UpperMS: 100}}, true, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		hc := DurableExecutionConfig{Root: root, Owner: owner, Clock: clock, Service: service, Store: store, Active: 2, TaskCharge: resourcev4.Vector{resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, RuntimeBytes: 4096, WorkRuntimeBytes: 4096}
		cost, err = DurableExecutionsCharge(hc)
		if err != nil {
			t.Fatal(err)
		}
		history, err = NewDurableExecutions(hc, reserve(cost))
		if err != nil {
			t.Fatal(err)
		}
	}
	closeStore := func() {
		cleanupContext, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if history != nil {
			history.Close()
			if err := history.Collect(ctx); err != nil {
				t.Error(err)
			}
			if !history.CleanupComplete() {
				t.Error("issuance history retained work")
			}
			history = nil
		}
		if store != nil {
			store.Close()
			if err := store.WaitCleanup(cleanupContext); err != nil {
				t.Error(err)
			}
			if err := store.Retire(); err != nil {
				t.Error(err)
			}
			store = nil
		}
	}
	t.Cleanup(closeStore)
	open(true)
	caller := ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}
	access := managementAccess{reserve(resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})}
	input := func(id byte) (*VerifiedInput, ExecutionTarget) {
		fields := protocolv4.ApplicationHeaderFields{Type: policy.Type, DeadlineAtMS: 500, ServiceContractDigest: policy.Digest, ResponseLimitBytes: 1024}
		binary.BigEndian.PutUint64(fields.OperationID[:], 100)
		fields.OperationID[31] = id
		codec, _ := protocolv4.NewApplicationHeaderCodec()
		var wire [512]byte
		_, h, err := codec.Encode(wire[:], "execution_unary_request", fields)
		if err != nil {
			t.Fatal(err)
		}
		fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(h, contract, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, h, err = codec.Encode(wire[:], "execution_unary_request", fields)
		if err != nil {
			t.Fatal(err)
		}
		ic := InputConfig{Clock: clock, Capture: true, RuntimeBytes: 1024, HashRuntimeBytes: 512}
		cost, _ := RequestInputCharge(h, ic)
		p, err := NewRequestInput(h, contract, ic, reserve(cost))
		if err != nil {
			t.Fatal(err)
		}
		// The test captures the registered method exactly as ServiceInputs does.
		p.method, p.methodBound, p.policy = 0, true, policy
		t.Cleanup(p.Close)
		if err = p.Finish(); err != nil {
			t.Fatal(err)
		}
		verified, err := p.Take()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(verified.Close)
		return verified, ExecutionTarget{Service: service, Caller: caller, Operation: fields.OperationID, RequestDigest: fields.RequestDigest, ContractDigest: policy.Digest}
	}
	// Failed direct admission must leave both the finite adapter and SQLite
	// unchanged so the same operation can later become the checkpoint source.
	for _, cause := range []string{"executor", "resources"} {
		t.Run("direct admission rollback/"+cause, func(t *testing.T) {
			in, target := input(1)
			defer in.Close()
			want := errors.New("executor unavailable")
			if cause == "resources" {
				snapshot := root.Snapshot()
				hold := reserve(resourcev4.Vector{resourcev4.SDKBytes: snapshot.Limit[resourcev4.SDKBytes] - snapshot.Charged[resourcev4.SDKBytes]})
				defer hold.Release()
				want = resourcev4.ErrCapacity
			}
			before := root.Snapshot()
			called := false
			observation, work, err := history.Admit(ctx, routes, in, caller, access, func(resourcev4.Reference, resourcev4.Reference) error {
				called = true
				if history.reserved != 1 || history.active != 0 {
					t.Error("missing pre-acquire execution reservation", history.reserved, history.active)
				}
				return want
			})
			if !errors.Is(err, want) || work != nil || observation.Found || called != (cause == "executor") {
				t.Fatal("unexpected failed admission", observation, work, err, called)
			}
			if history.reserved != 0 || history.active != 0 || history.calls != 0 || routes.captures != 0 || in.borrowed {
				t.Error("failed admission retained capacity or input", history.reserved, history.active, history.calls, routes.captures, in.borrowed)
			}
			if after := root.Snapshot(); after != before {
				t.Error("failed admission retained resources", before, after)
			}
			if observation, err := history.Query(ctx, target, access); err != nil || observation.Found {
				t.Error("failed admission persisted an execution", observation, err)
			}
		})
	}
	if t.Failed() {
		return
	}
	enter := func(id byte) (*DurableExecutionWork, ExecutionTarget, func()) {
		in, target := input(id)
		var task resourcev4.Reference
		_, work, err := history.Admit(ctx, routes, in, caller, access, func(ref, _ resourcev4.Reference) error {
			if history.reserved != 1 || history.active != 0 {
				return errors.New("durable execution history was not reserved before executor acquire")
			}
			task = ref
			return nil
		})
		if err != nil || work == nil {
			t.Fatal("admit issuance", err)
		}
		done := make(chan struct{})
		if err = work.SubmitTask(func() (<-chan struct{}, error) { return done, nil }); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		end := func() {
			once.Do(func() {
				close(done)
				task.Release()
				if err := work.Exit(ctx); err != nil {
					t.Error(err)
				}
			})
		}
		t.Cleanup(end)
		if _, err = work.Enter(ctx); err != nil {
			t.Fatal(err)
		}
		return work, target, end

	}
	originalWork, original, endOriginal := enter(1)
	if err = originalWork.Finish(ctx, 0, []byte("checkpoint source")); err != nil {
		t.Fatal(err)
	}
	endOriginal()
	key, err := cryptov4.ImportRecoveryMACKey([32]byte{7}, reserve(cryptov4.RecoveryMACKeyCharge()))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	vc := RecoveryVerifierConfig{Service: service, Clock: clock, Keys: []RecoveryKey{{ID: [16]byte{1}, Protection: 1, MAC: key}}, RuntimeBytes: 4096}
	cost, _ = RecoveryVerifierCharge(vc)
	verifier, err := NewRecoveryVerifier(vc, reserve(cost))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	checkpoint, err := verifier.codec.CaptureCheckpoint("offset", []byte{42})
	if err != nil {
		t.Fatal(err)
	}
	work, issuance, endIssuance := enter(2)
	options := RecoveryIssuance{DurationMS: 100, ApplicationDurationLimitMS: 200, HistoryNotAfterMS: 500, SessionPolicy: protocolv4.ResumePolicy{Enabled: true, MaxIssuedTokenDurationMS: 200, MaxTokenBytes: 1024}}
	if err = work.IssueRecoveryToken(ctx, verifier, [16]byte{1}, original, checkpoint, options); err != nil {
		t.Fatal("current unary header could not issue token", err)
	}
	if !work.ResultCommitted() {
		t.Fatal("issuance did not commit result")
	}
	if err = work.IssueRecoveryToken(ctx, verifier, [16]byte{1}, original, checkpoint, options); !errors.Is(err, ErrOwner) {
		t.Fatal("issuance ran twice", err)
	}
	endIssuance()
	var saved [1024]byte
	_, size, err := history.ReadResult(ctx, issuance, access, saved[:])
	if err != nil || size == 0 {
		t.Fatal("missing durable token", err)
	}
	token, err := verifier.codec.DecodeToken(saved[:size], 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.codec.VerifyMACToken(token, [16]byte{1}, key, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if token.Claims().Operation != original.Operation || token.Claims().ExpiresAtMS != 125 {
		t.Fatal("issuance changed original binding or expiry")
	}
	for _, reopen := range []bool{false, true} {
		if reopen {
			closeStore()
			open(false)
		}
		duplicate, _ := input(2)
		observed, again, err := history.Admit(ctx, routes, duplicate, caller, access, func(resourcev4.Reference, resourcev4.Reference) error { t.Error("duplicate acquired task"); return nil })
		if err != nil || again != nil || observed.State != ExecutionCompleted {
			t.Fatal("duplicate reentered issuance", observed, err)
		}
		var restored [1024]byte
		_, n, err := history.ReadResult(ctx, issuance, access, restored[:])
		if err != nil || n != size || !bytes.Equal(saved[:size], restored[:n]) {
			t.Fatal("read/restart renewed or lost token", err)
		}
	}
}
