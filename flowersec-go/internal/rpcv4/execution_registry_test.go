package rpcv4

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func executionClock(t *testing.T) *timev4.Clock {
	t.Helper()
	var tick atomic.Uint64
	c, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	mark, err := c.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	return c
}

func executionRoot(t *testing.T) *resourcev4.Root {
	t.Helper()
	r, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 2, ReservationSlots: 64, ReferenceSlots: 128, Limit: resourcev4.Vector{resourcev4.SDKBytes: 1 << 28, resourcev4.Items: 10000, resourcev4.Tasks: 100, resourcev4.WorkSlots: 100}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestExecutionContinuityIsChargedAndDetachesAliases(t *testing.T) {
	r := executionRoot(t)
	clock := executionClock(t)
	cfg := VolatileExecutionConfig{Root: r, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{2}, Backing: [16]byte{3}, Kind: 7}, Clock: clock, Service: ExecutionService{"tenant", "audience", "files"}, CallerAuthorities: [][32]byte{{4}}, Records: 4, Active: 2, TaskCharge: resourcev4.Vector{resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Items: 1}, RuntimeBytes: 4096, WorkRuntimeBytes: 4096, ResultRuntimeBytes: 4096}
	charge, err := VolatileExecutionsCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := r.Reserve(cfg.Owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewVolatileExecutions(cfg, meta)
	if err != nil {
		t.Fatal(err)
	}
	continuityCharge, err := ExecutionContinuityCharge(1024)
	if err != nil {
		t.Fatal(err)
	}
	continuityOwner := cfg.Owner
	continuityOwner.Instance = [16]byte{11}
	continuityOwner.Backing = [16]byte{12}
	continuityMeta, err := r.Reserve(continuityOwner, continuityCharge)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := s.Continuity(continuityMeta, 1024)
	if err != nil {
		t.Fatal(err)
	}
	alias := cc
	s.Close()
	if s.CleanupComplete() {
		t.Fatal("store dropped while continuity was retained")
	}
	cc.Close()
	alias.Close()
	if !s.CleanupComplete() {
		t.Fatal("continuity release did not detach and permit cleanup")
	}
	meta.Release()
	continuityMeta.Release()
}

func TestServiceRegistryRejectsSecondLiveAuthority(t *testing.T) {
	r := executionRoot(t)
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{5}, Backing: [16]byte{6}, Kind: 8}
	c := ServiceRegistryConfig{Root: r, Owner: owner, Entries: 1, RuntimeBytes: 1024}
	charge, err := ServiceRegistryCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := r.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewServiceRegistry(c, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	clock := executionClock(t)
	historyOwner := owner
	historyOwner.Instance = [16]byte{9}
	historyOwner.Backing = [16]byte{10}
	vc := VolatileExecutionConfig{Root: r, Owner: historyOwner, Clock: clock, Service: ExecutionService{"tenant", "audience", "files"}, CallerAuthorities: [][32]byte{{7}}, Records: 1, Active: 1, TaskCharge: resourcev4.Vector{resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, RuntimeBytes: 1024, WorkRuntimeBytes: 1024, ResultRuntimeBytes: 1024}
	vcharge, err := VolatileExecutionsCharge(vc)
	if err != nil {
		t.Fatal(err)
	}
	href, err := r.Reserve(historyOwner, vcharge)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewVolatileExecutions(vc, href)
	if err != nil {
		t.Fatal(err)
	}
	a := ServiceAuthority{"tenant", "audience", "files"}
	wrong := a
	wrong.Namespace = "other"
	if err := reg.Bind(ServiceBinding{Authority: wrong, History: h}); !errors.Is(err, ErrAssociation) {
		t.Fatal("bound unrelated authority", err)
	}
	if err := reg.Bind(ServiceBinding{Authority: a, History: h}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Bind(ServiceBinding{Authority: a, History: h}); !errors.Is(err, ErrServiceAlreadyBound) {
		t.Fatal(err)
	}
	if err := reg.Unbind(a, h); !errors.Is(err, ErrCapacity) {
		t.Fatal("replaced live history", err)
	}
	charge, _ = ExecutionContinuityCharge(512)
	continuityOwner := historyOwner
	continuityOwner.Instance = [16]byte{11}
	continuityOwner.Backing = [16]byte{12}
	continuityRef, err := r.Reserve(continuityOwner, charge)
	if err != nil {
		t.Fatal(err)
	}
	continuity, err := h.Continuity(continuityRef, 512)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	if err := reg.Unbind(a, h); !errors.Is(err, ErrCapacity) {
		t.Fatal("replaced captured history", err)
	}
	continuity.Close()
	continuityRef.Release()
	if err := reg.Unbind(a, h); err != nil {
		t.Fatal(err)
	}
	meta.Release()
}
