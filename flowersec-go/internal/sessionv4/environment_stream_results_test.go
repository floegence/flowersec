package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func unpublishedStreamResult(t *testing.T, f *serviceDispatchFixture, r *RPCServices, floor *CompletionFloor) *StreamMessages {
	t.Helper()
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(initialFixture(t, "service_stream_transient"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(contract.Release)
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	var wire [512]byte
	_, header, err := f.codec.Encode(wire[:], "transient_stream_request", protocolv4.ApplicationHeaderFields{Type: policy.Type, ServiceContractDigest: policy.Digest, PayloadBytes: 3, DeadlineAtMS: 2000, ResponseLimitBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := timev4.NewDeadline(f.trust.clock, 2000)
	if err != nil {
		t.Fatal(err)
	}
	config := StreamMessagesConfig{HardDeadline: deadline, Request: header, RuntimeBytes: 4096}
	if floor != nil {
		config.Result = &StreamResultConfig{Executor: f.f.executor, Decode: synchronousResult, completionFloor: floor}
	}
	charge, err := StreamMessagesCharge(policy, config)
	if err != nil {
		t.Fatal(err)
	}
	_, authority, err := r.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	deliveryCharge, err := protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := authority.ForkDelivery(f.f.reserve(t, 1, deliveryCharge))
	if err != nil {
		t.Fatal(err)
	}
	m, err := prepareStreamMessages(contract, config, f.f.reserveOwner(t, 1, charge, true), delivery)
	if err != nil {
		delivery.Close(err)
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func TestEnvironmentStreamResultUsesOriginalSharedFiniteTable(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	positions := make([]environmentResultProtection, len(e.results)-1) // The original short result owns one.
	if err := e.protectResults(e.reservation, positions); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, p := range positions {
			p.close()
		}
	}()
	m := unpublishedStreamResult(t, f, r, nil)
	before := f.f.root.Snapshot()
	if err := e.admitStreamResult(m, environmentResultProtection{}); !errors.Is(err, cryptov4.ErrCapacity) || f.f.root.Snapshot() != before {
		t.Fatal("stream consumed another result's declared position", err)
	}
	p := positions[0]
	if err := e.admitStreamResult(m, p); err != nil {
		t.Fatal(err)
	}
	defer m.finishEnvironmentPreparation()
	if err := e.admitStreamResult(m, p); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("same stream acquired a second result position", err)
	}
	p.close()
	results := f.f.root.Snapshot().ResultOwners
	m.Close()
	// The table's original pin survives logical payload cleanup until the
	// existing coordinator actually observes that constructor's final exit.
	e.mu.Lock()
	slot, err := p.slotLocked()
	retained := err == nil && slot.stream == m && slot.pin != (resourcev4.Reference{}) && f.f.root.Snapshot().ResultOwners == results
	e.mu.Unlock()
	if !retained {
		t.Fatal("declaration close refunded a still registered result", err)
	}
	m.finishEnvironmentPreparation()
	e.advanceResults()
	if e.OperationsSnapshot().ActiveResults != 0 {
		t.Fatal("original result cleanup did not retire its Environment position")
	}
	var replacement [1]environmentResultProtection
	if err := e.protectResults(e.reservation, replacement[:]); err != nil {
		t.Fatal(err)
	}
	defer replacement[0].close()
	p.close()
	e.mu.Lock()
	_, err = replacement[0].slotLocked()
	e.mu.Unlock()
	if err != nil {
		t.Fatal("stale stream declaration closed its replacement", err)
	}
}

func TestEnvironmentStreamConstructionCloseFencesDeliveryBeforeCleanup(t *testing.T) {
	f, r, _, e := deferredCallerFixture(t)
	m := unpublishedStreamResult(t, f, r, nil)
	if err := e.admitStreamResult(m, environmentResultProtection{}); err != nil {
		t.Fatal(err)
	}
	defer m.finishEnvironmentPreparation()
	e.Close()
	if m.Status().CleanupComplete {
		t.Fatal("Environment cleaned an unpublished constructor's mutable state")
	}
	entered := false
	if err := m.withCurrentAuthorization(func() error { entered = true; return nil }); !errors.Is(err, cryptov4.ErrClosed) || entered {
		t.Fatal("closed Environment permitted a late handoff", err, entered)
	}
	m.finishEnvironmentPreparation()
	e.advanceResults()
	if !m.Status().CleanupComplete || e.OperationsSnapshot().ActiveResults != 0 {
		t.Fatal("actual constructor exit did not join original result cleanup")
	}
}

func TestStreamResultReturnsBorrowedCompletionOnlyAfterWholeUse(t *testing.T) {
	f, r, _, _ := deferredCallerFixture(t)
	executor := f.f.executor
	floor, err := executor.NewCompletionFloor(f.f.reserve(t, 1, executor.CompletionFloorCharge()), f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 1024}))
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	for range 2 {
		m := unpublishedStreamResult(t, f, r, floor)
		m.result.future.Close()
		m.result.future = nil
		if err := floor.checkAvailable(); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("between-item stream returned its whole workload vector", err)
		}
		if err := m.ensureStreamFutureLocked(); err != nil {
			t.Fatal("original stream lost its next future", err)
		}
		m.Close()
		if !m.Status().CleanupComplete || floor.checkAvailable() != nil {
			t.Fatal("finished stream closed its borrowed workload floor")
		}
	}
}
