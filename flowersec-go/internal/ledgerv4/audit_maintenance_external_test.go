package ledgerv4_test

import (
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"math"
	"testing"
	"time"
)

func maintenance(t *testing.T, h *ledgerv4.AuditMaintenanceHarness) *controlv4.AuditMaintenance {
	t.Helper()
	c := controlv4.AuditMaintenanceConfig{Source: h.Source, Archive: h.Archive, SourceAccess: h.SourceAccess, ArchiveAccess: h.ArchiveAccess, Clock: h.Clock, ExportEveryMS: 2000, RetentionEveryMS: 1000, CallMS: 1000, RuntimeBytes: 65536, RuntimeBytesPerTask: 65536}
	cost, err := controlv4.AuditMaintenanceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := controlv4.NewAuditMaintenance(c, h.Reserve(cost), h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return p
}
func waitMaintenance(t *testing.T, check func() bool) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-timeout.C:
			t.Fatal("bounded maintenance condition not reached")
		case <-tick.C:
		}
	}
}
func TestAuditMaintenanceAutomaticallyExportsAndExpiresOriginalRecords(t *testing.T) {
	h := ledgerv4.NewAuditMaintenanceHarness(t)
	h.Prepare(t)
	p := maintenance(t, h)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("maintenance state: %+v", p.Snapshot())
		}
	})
	waitMaintenance(t, func() bool { return p.Snapshot().PagesAcknowledged > 0 })
	// Inspect persistence after stopping native maintenance briefly through its
	// normal service lifecycle; source and archive owners remain independently live.
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := h.Archive.AuditArchiveStatus(context.Background(), h.ArchiveAccess)
	if err != nil || status.Records != 1 {
		t.Fatal("automatic export did not persist original outbox", status, err)
	}
	h.Tick(1000)
	q := maintenance(t, h)
	waitMaintenance(t, func() bool {
		s := q.Snapshot()
		return s.LastSourceRetention == "complete" && s.LastArchiveRetention == "complete"
	})
	q.Close()
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	status, err = h.Archive.AuditArchiveStatus(context.Background(), h.ArchiveAccess)
	if err != nil || status.Records != 0 {
		t.Fatal("automatic retention reset original TTL", status, err)
	}
	source, err := h.Source.AuditStatus(context.Background(), h.SourceAccess)
	if err != nil || source.OrdinaryRecords != 0 {
		t.Fatal("source retention not independently executed", source, err)
	}
}
func TestAuditMaintenanceBlockedArchiveRetainsItsOriginalWorkers(t *testing.T) {
	h := ledgerv4.NewAuditMaintenanceHarness(t)
	h.Prepare(t)
	entered, release := h.BlockArchiveCommit()
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	p := maintenance(t, h)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original archive operation not reached")
	}
	// The independent source-retention worker can still run while the archive
	// driver is physically blocked; no replacement export worker is created.
	waitMaintenance(t, func() bool { return p.Snapshot().SourceRetentionCalls > 0 })
	before := h.Root.Snapshot().Charged
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := p.WaitCleanup(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || h.Root.Snapshot().Charged != before {
		t.Fatal("service refunded original blocked driver/worker", err)
	}
	c := controlv4.AuditMaintenanceConfig{Source: h.Source, Archive: h.Archive, SourceAccess: h.SourceAccess, ArchiveAccess: h.ArchiveAccess, Clock: h.Clock, ExportEveryMS: 2000, RetentionEveryMS: 1000, CallMS: 1000, RuntimeBytes: 65536, RuntimeBytesPerTask: 65536}
	cost, chargeErr := controlv4.AuditMaintenanceCharge(c)
	if chargeErr != nil {
		t.Fatal(chargeErr)
	}
	reservation, dependencies := h.Reserve(cost), h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536})
	duplicate, duplicateErr := controlv4.NewAuditMaintenance(c, reservation, dependencies)
	reservation.Release()
	dependencies.Release()
	if duplicate != nil {
		duplicate.Close()
	}
	if !errors.Is(duplicateErr, ledgerv4.ErrCapacity) {
		t.Fatal("logical closure admitted duplicate original scheduler", duplicateErr)
	}
	if snapshot := p.Snapshot(); snapshot.CleanupComplete || !snapshot.ExportRunning && !snapshot.ArchiveRetentionRunning {
		t.Fatal("logical close asserted physical completion")
	}
	release()
	released = true
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if !p.Snapshot().CleanupComplete || h.Root.Snapshot().Charged[resourcev4.SDKBytes] >= before[resourcev4.SDKBytes] {
		t.Fatal("real worker exit retained service charge")
	}
}
func TestAuditMaintenanceRejectsRevokedBindingAndOverflowBeforeStart(t *testing.T) {
	h := ledgerv4.NewAuditMaintenanceHarness(t)
	c := controlv4.AuditMaintenanceConfig{Source: h.Source, Archive: h.Archive, SourceAccess: h.SourceAccess, ArchiveAccess: h.ArchiveAccess, Clock: h.Clock, ExportEveryMS: 2000, RetentionEveryMS: 1000, CallMS: 1000, RuntimeBytes: 65536, RuntimeBytesPerTask: math.MaxUint64 / 3}
	if _, err := controlv4.AuditMaintenanceCharge(c); err == nil {
		t.Fatal("runtime charge overflow accepted")
	}
	c.RuntimeBytesPerTask = 65536
	cost, err := controlv4.AuditMaintenanceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	h.RevokeArchive()
	p, err := controlv4.NewAuditMaintenance(c, h.Reserve(cost), h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536}))
	if p != nil {
		p.Close()
	}
	if !errors.Is(err, ledgerv4.ErrAuditDenied) {
		t.Fatal("revoked maintenance scope admitted", err)
	}
}
