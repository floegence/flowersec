package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type liveRetirementPolicy struct {
	allow atomic.Bool
	calls atomic.Uint32
}

func (p *liveRetirementPolicy) CanRetireLiveSpend(_ SQLiteIdentity, row LiveSpendRetirement, proof []byte) (bool, error) {
	p.calls.Add(1)
	if row.ParentInitiationEndMS != 109000 || row.ParentSessionEndMS != 120000 || row.Outcome == AuthorizationAuthorized && len(proof) == 0 {
		return false, ErrConfiguration
	}
	return p.allow.Load(), nil
}

func liveMaintenance(t *testing.T, f *liveReadFixture, policy LiveSpendRetirementPolicy) *SQLiteLiveMaintenance {
	t.Helper()
	c := LiveMaintenanceConfig{BatchRows: 2, RuntimeBytes: 65536, Retirement: policy}
	charge, err := SQLiteLiveMaintenanceCharge(f.backing.limits.MaxRecordBytes, c)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewSQLiteLiveMaintenance(context.Background(), f.store, f.time.clock, c, f.reserve(charge, 1), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func liveMaintenanceTime(t *testing.T, f *liveReadFixture, milliseconds uint64) {
	t.Helper()
	f.advance.Store(milliseconds)
	mark, err := f.time.clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.time.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100000 + milliseconds, UpperMS: 100000 + milliseconds}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteLiveMaintenanceRecoversOnlyExpiredOriginalIntent(t *testing.T) {
	f := newLiveReadFixture(t, false, 0)
	m := liveMaintenance(t, f, nil)
	status, err := m.RunBatch(context.Background())
	if err != nil || status.Recovered != 0 || status.Scanned != 1 {
		t.Fatal(status, err)
	}
	liveMaintenanceTime(t, f, 1500)
	status, err = m.RunBatch(context.Background())
	if err != nil || status.Recovered != 1 || status.Removed != 0 {
		t.Fatal(status, err)
	}
	var storage [65536]byte
	row, err := f.store.readLiveSpend(f.key, storage[:])
	if err != nil || !row.consumed || row.outcome != 0 || len(row.proof) != 0 || !bytes.Equal(row.spending, f.spending) {
		t.Fatal("recovery changed original intent", row, err)
	}
	status, err = m.RunBatch(context.Background())
	if err != nil || status.Recovered != 1 {
		t.Fatal("terminal row was recovered again", status, err)
	}
}

func TestSQLiteLiveMaintenanceRetainsTimeEligibleEvidenceUntilPolicyRetirement(t *testing.T) {
	f := newLiveReadFixture(t, true, 2)
	policy := &liveRetirementPolicy{}
	m := liveMaintenance(t, f, policy)
	liveMaintenanceTime(t, f, liveSpendRetentionMS+8999)
	status, err := m.RunBatch(context.Background())
	if err != nil || status.Removed != 0 || policy.calls.Load() != 0 {
		t.Fatal("GC used material deadline instead of parent initiation", status, err)
	}
	liveMaintenanceTime(t, f, liveSpendRetentionMS+9000)
	status, err = m.RunBatch(context.Background())
	if err != nil || status.Removed != 0 || policy.calls.Load() == 0 {
		t.Fatal("GC bypassed actual reference policy", status, err)
	}
	policy.allow.Store(true)
	status, err = m.RunBatch(context.Background())
	if err != nil || status.Removed != 1 {
		t.Fatal(status, err)
	}
	count, err := f.store.scalar("SELECT spend_rows FROM manifest WHERE id=1")
	if err != nil || count != int64(0) {
		t.Fatal("GC did not release record quota", count, err)
	}
	count, err = f.store.scalar("SELECT count(*) FROM spend")
	if err != nil || count != int64(0) {
		t.Fatal(count, err)
	}
}

func TestSQLiteLiveMaintenanceUnavailableTimeAndStoreNeverLooksEmpty(t *testing.T) {
	f := newLiveReadFixture(t, false, 0)
	m := liveMaintenance(t, f, nil)
	f.advance.Store(70000)
	status, err := m.RunBatch(context.Background())
	if err == nil || !status.Unavailable || status.Recovered != 0 {
		t.Fatal(status, err)
	}
	liveMaintenanceTime(t, f, 70000)
	if err = f.store.begin(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err = m.RunBatch(context.Background())
	f.store.end()
	if !errors.Is(err, ErrCapacity) || !status.Unavailable {
		t.Fatal(status, err)
	}
	status, err = m.RunBatch(context.Background())
	if err != nil || status.Recovered != 1 || status.Unavailable {
		t.Fatal(status, err)
	}
}
