package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type auditArchiveFixture struct {
	*sqliteFixture
	config  SQLiteAuditArchiveConfig
	clock   *timev4.Clock
	tick    atomic.Uint64
	archive *SQLiteAuditArchive
	access  *auditAccessFixture
}

func newAuditArchiveFixture(t *testing.T, records uint32, source ...*topUpServerFixture) *auditArchiveFixture {
	t.Helper()
	f := &auditArchiveFixture{sqliteFixture: newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 64, MaxRecords: records, MaxRecordBytes: 1024, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})}
	var err error
	f.clock, err = timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 1 << 40, MaxRoundTripMS: 100}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: f.tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.clock.Close)
	mark, _ := f.clock.Monotonic()
	if err := f.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100, UpperMS: 100}); err != nil {
		t.Fatal(err)
	}
	f.config = SQLiteAuditArchiveConfig{Source: SQLiteIdentity{Authority: "source-test", StoreID: [32]byte{41}, Generation: 1}, Tenant: "tenant-1", Object: [16]byte{1}, Records: records, RetentionMS: 1000, RequestsPerMinute: 60, Clock: f.clock}
	if len(source) != 0 {
		f.config.Source = source[0].identity
		f.config.Tenant = source[0].config.Tenant
		f.config.Object = source[0].config.Source
	}
	f.access = &auditAccessFixture{identity: f.identity, tenant: f.config.Tenant}
	f.access.role.Store(2)
	f.access.permissions.Store(1<<AuditOutboxExport | 1<<AuditOperationsRead | 1<<AuditRetentionMaintenance)
	f.open(true)
	return f
}
func (f *auditArchiveFixture) open(create bool) {
	f.t.Helper()
	charge, err := SQLiteAuditArchiveCharge(f.backing.limits, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	reservation := f.reserve(charge, 1)
	if create {
		f.archive, err = CreateSQLiteAuditArchive(context.Background(), f.backing, f.identity, f.continuity, f.config, reservation, f.environment)
	} else {
		f.archive, err = OpenSQLiteAuditArchive(context.Background(), f.backing, f.identity, f.continuity, f.config, reservation, f.environment)
	}
	if f.archive != nil {
		f.stores = append(f.stores, f.archive.store)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *auditArchiveFixture) closeArchive() {
	f.t.Helper()
	f.archive.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.archive.WaitCleanup(ctx); err != nil {
		f.t.Fatal(err)
	}
	if err := f.archive.Retire(); err != nil {
		f.t.Fatal(err)
	}
}
func archivePage(n int) AuditPage {
	p := AuditPage{Count: uint16(n), Complete: true, NextSequence: uint64(n), ThroughSequence: uint64(n)}
	for i := range n {
		p.Records[i] = AuditRecord{EventID: [16]byte{byte(i + 1)}, UTCMS: 100, Principal: AuditPrincipal{Actor: [32]byte{7}, Role: 1}, Tenant: "tenant-1", Action: AuditMaterialIssued, Object: [16]byte{1}, BeforeVersion: uint64(i), AfterVersion: uint64(i + 1)}
		p.Sequences[i] = uint64(i + 1)
	}
	return p
}
func (f *auditArchiveFixture) count() uint32 {
	f.t.Helper()
	status, err := f.archive.AuditArchiveStatus(context.Background(), f.access)
	if err != nil {
		f.t.Fatal(err)
	}
	return status.Records
}
func TestAuditArchivePersistDeduplicatesAcrossActualReopen(t *testing.T) {
	f := newAuditArchiveFixture(t, 4)
	page := archivePage(2)
	for range 2 {
		receipts, count, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page)
		if err != nil || count != 2 || receipts[0].EventID != page.Records[0].EventID || receipts[1].Sequence != 2 {
			t.Fatal("original page not committed", count, err)
		}
	}
	if f.count() != 2 {
		t.Fatal("retry duplicated records")
	}
	f.closeArchive()
	f.open(false)
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page); err != nil || n != 2 || f.count() != 2 {
		t.Fatal("reopen lost event-ID dedup", err)
	}
	for _, mutate := range []func(*AuditPage){
		func(p *AuditPage) { p.Records[0].Principal.Actor[1] = 9 },
		func(p *AuditPage) { p.Records[0].EventID[1] = 9 },
		func(p *AuditPage) { p.Sequences[0] = 3; p.Count = 1 },
	} {
		changed := page
		mutate(&changed)
		if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, changed); err == nil || n != 0 || f.count() != 2 {
			t.Fatal("conflicting retry changed archive", n, err)
		}
	}
}
func TestAuditArchiveUnknownCommitRetriesOriginalIDs(t *testing.T) {
	f := newAuditArchiveFixture(t, 4)
	page := archivePage(2)
	original := f.archive.store.execer
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("private lost commit detail") }}
	fault.commits.Store(1)
	f.archive.store.execer = fault
	receipts, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page)
	if !errors.Is(err, ErrAuditUnknown) || n != 0 || receipts != ([AuditPageRecords]AuditExportReceipt{}) {
		t.Fatal("lost commit manufactured receipt", n, err)
	}
	f.archive.store.execer = original
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page); err != nil || n != 2 || f.count() != 2 {
		t.Fatal("unknown commit replay duplicated/lost records", err)
	}
}
func TestAuditArchiveFullPageRollsBackAndKeepsExactDuplicates(t *testing.T) {
	f := newAuditArchiveFixture(t, 1)
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, archivePage(2)); !errors.Is(err, ErrAuditCapacity) || n != 0 || f.count() != 0 {
		t.Fatal("partial page escaped capacity refusal", n, err)
	}
	for range 2 {
		if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, archivePage(1)); err != nil || n != 1 {
			t.Fatal("exact retry failed at cap", n, err)
		}
	}
	if f.count() != 1 {
		t.Fatal("duplicate appended at cap")
	}
}
func TestAuditArchivePermissionsAndOriginalTimeAreCheckedBeforeCommit(t *testing.T) {
	f := newAuditArchiveFixture(t, 4)
	for _, mutate := range []func(*AuditPage){
		func(p *AuditPage) { p.Records[0].Tenant = "other-tenant" },
		func(p *AuditPage) { p.Records[0].Object = [16]byte{8} },
		func(p *AuditPage) { p.Records[0].UTCMS = 101 },
		func(p *AuditPage) { p.Records[0].UTCMS = math.MaxUint64 },
		func(p *AuditPage) { p.Sequences[0] = 0 },
	} {
		page := archivePage(1)
		mutate(&page)
		if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page); err == nil || n != 0 {
			t.Fatal("foreign/unbounded record accepted", n, err)
		}
	}
	source := f.config.Source
	source.Generation++
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, source, archivePage(1)); err == nil || n != 0 {
		t.Fatal("different source incarnation accepted")
	}
	f.access.permissions.Store(1 << AuditOperationsRead)
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, archivePage(1)); !errors.Is(err, ErrAuditDenied) || n != 0 {
		t.Fatal("ordinary operations reader appended security record", err)
	}
	f.access.permissions.Store(1<<AuditOutboxExport | 1<<AuditOperationsRead)
	if err := f.archive.ExpireAuditArchive(context.Background(), f.access); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("export permission deleted records", err)
	}
	original := f.archive.store.execer
	f.archive.store.execer = &auditExecFault{ExecerContext: original, prefix: "INSERT INTO archived_events", after: func() error { f.access.revoked.Store(true); return nil }}
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, archivePage(1)); !errors.Is(err, ErrAuditDenied) || n != 0 {
		t.Fatal("permission revoked during SQL committed", err)
	}
	f.archive.store.execer = original
	f.access.revoked.Store(false)
	if f.count() != 0 {
		t.Fatal("revoked transaction did not roll back")
	}
}
func TestAuditArchiveExpiryUsesOriginalDeadlineAndClearsDisk(t *testing.T) {
	f := newAuditArchiveFixture(t, 4)
	page := archivePage(1)
	marker := []byte("private-archive-actor-7dc81972")
	copy(page.Records[0].Principal.Actor[:], marker)
	if _, _, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page); err != nil {
		t.Fatal(err)
	}
	f.tick.Store(999)
	if err := f.archive.ExpireAuditArchive(context.Background(), f.access); err != nil || f.count() != 1 {
		t.Fatal("record deleted before original deadline", err)
	}
	if _, _, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page); err != nil {
		t.Fatal("last valid retry failed", err)
	}
	f.tick.Store(1000)
	if err := f.archive.ExpireAuditArchive(context.Background(), f.access); err != nil || f.count() != 0 {
		t.Fatal("retry extended retention", err)
	}
	if _, n, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, page); err == nil || n != 0 {
		t.Fatal("expired event resurrected")
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(f.backing.path + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, marker) {
			t.Fatal("successful physical deletion retained original actor", suffix)
		}
	}
	f.closeArchive()
	f.open(false)
	if f.count() != 0 {
		t.Fatal("reopen restored expired record")
	}
}
func TestAuditArchiveInterruptedExpiryDoesNotReportPhysicalDeletion(t *testing.T) {
	f := newAuditArchiveFixture(t, 4)
	if _, _, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, archivePage(1)); err != nil {
		t.Fatal(err)
	}
	f.tick.Store(1000)
	original := f.archive.store.execer
	f.archive.store.execer = &auditExecFault{ExecerContext: original, prefix: "DELETE FROM archived_events", before: func() error { return errors.New("private disk failure") }}
	if err := f.archive.ExpireAuditArchive(context.Background(), f.access); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatal("storage failure reported cleanup", err)
	}
	f.archive.store.execer = original
	if f.count() != 1 {
		t.Fatal("failed transaction discarded original record")
	}
	if err := f.archive.ExpireAuditArchive(context.Background(), f.access); err != nil || f.count() != 0 {
		t.Fatal("retention did not resume", err)
	}
}

// Test-only raw-page insertion exercises storage rejection independently of the
// production transfer, which obtains records directly from the source outbox.
func (a *SQLiteAuditArchive) persistTestPage(ctx context.Context, access AuditAccess, source SQLiteIdentity, page AuditPage) ([AuditPageRecords]AuditExportReceipt, uint16, error) {
	principal, err := a.begin(ctx, access, AuditOutboxExport)
	if err != nil {
		return [AuditPageRecords]AuditExportReceipt{}, 0, err
	}
	defer a.store.end()
	return a.persistPage(ctx, access, principal, source, page, nil)
}

func TestAuditArchiveTransfersActualOutboxOnlyAfterConfirmedPersistence(t *testing.T) {
	source := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 1000})
	_, wire := source.request(1, 1)
	if _, err := source.prepare(wire); err != nil {
		t.Fatal(err)
	}
	f := newAuditArchiveFixture(t, 4, source)
	sourceAccess := newAuditAccess(source, AuditOutboxExport)
	original := f.archive.store.execer
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost archive commit confirmation") }}
	fault.commits.Store(1)
	f.archive.store.execer = fault
	result, err := f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery())
	if !errors.Is(err, ErrAuditUnknown) || result.Persistence != "unknown" || result.Acknowledgement != "not_started" || result.NextSequence != 0 || auditMetaForTest(t, source).ordinaryPending != 1 {
		t.Fatal("unknown archive commit acknowledged source", result, err)
	}
	f.archive.store.execer = original
	result, err = f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery())
	if err != nil || result.Persistence != "committed" || result.Acknowledgement != "committed" || result.Count != 1 || !result.Complete || f.count() != 1 || auditMetaForTest(t, source).ordinaryPending != 0 {
		t.Fatal("actual outbox retry lost original event", result, err)
	}
	result, err = f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery())
	if err != nil || result.Count != 0 || result.Persistence != "not_started" || f.count() != 1 {
		t.Fatal("export replay invented another record", result, err)
	}
}
func TestAuditArchiveAcknowledgementInterruptionKeepsPersistedFact(t *testing.T) {
	source := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 1000})
	_, wire := source.request(1, 1)
	if _, err := source.prepare(wire); err != nil {
		t.Fatal(err)
	}
	f := newAuditArchiveFixture(t, 4, source)
	sourceAccess := newAuditAccess(source, AuditOutboxExport)
	original := source.server.store.execer
	source.server.store.execer = &auditExecFault{ExecerContext: original, prefix: "UPDATE audit_events SET exported", before: func() error { return errors.New("source ACK disk failure") }}
	result, err := f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery())
	if err == nil || result.Persistence != "committed" || result.Acknowledgement != "unknown" || result.NextSequence != 0 || f.count() != 1 || auditMetaForTest(t, source).ordinaryPending != 1 {
		t.Fatal("ACK failure lost original persistence/pending facts", result, err)
	}
	source.server.store.execer = original
	if result, err = f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery()); err != nil || result.Acknowledgement != "committed" || f.count() != 1 {
		t.Fatal("ACK retry duplicated archive", result, err)
	}
}
func TestAuditArchiveTransferBindsSourceRetentionAndCurrentPermissions(t *testing.T) {
	source := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 2000})
	_, wire := source.request(1, 1)
	if _, err := source.prepare(wire); err != nil {
		t.Fatal(err)
	}
	f := newAuditArchiveFixture(t, 4, source)
	sourceAccess := newAuditAccess(source, AuditOutboxExport)
	if result, err := f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery()); !errors.Is(err, ErrAuditDenied) || result.Persistence != "not_started" || f.count() != 0 {
		t.Fatal("mismatched original retention accepted", result, err)
	}
}

func TestAuditArchiveCloseKeepsBlockedCommitAndSourcePending(t *testing.T) {
	source := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 1000})
	_, wire := source.request(1, 1)
	if _, err := source.prepare(wire); err != nil {
		t.Fatal(err)
	}
	f := newAuditArchiveFixture(t, 4, source)
	sourceAccess := newAuditAccess(source, AuditOutboxExport)
	fault := &topUpServerCommitTail{ExecerContext: f.archive.store.execer, entered: make(chan struct{}), release: make(chan struct{})}
	f.archive.store.execer = fault
	done := make(chan error, 1)
	go func() {
		_, err := f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery())
		done <- err
	}()
	select {
	case <-fault.entered:
	case <-time.After(time.Second):
		t.Fatal("archive commit not reached")
	}
	before := f.root.Snapshot()
	f.archive.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := f.archive.WaitCleanup(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || f.root.Snapshot() != before {
		close(fault.release)
		t.Fatal("blocked original export refunded", err)
	}
	if result, err := f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery()); err == nil || result.Persistence != "not_started" {
		close(fault.release)
		t.Fatal("closed archive admitted another transfer")
	}
	close(fault.release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrAuditUnknown) {
			t.Fatal("lost commit manufactured certainty", err)
		}
	case <-time.After(time.Second):
		t.Fatal("actual commit did not return")
	}
	f.closeArchive()
	if auditMetaForTest(t, source).ordinaryPending != 1 {
		t.Fatal("unknown archive commit acknowledged source")
	}
}
func TestAuditArchiveRestoreRejectsChangedBindingAndCorruptExpiry(t *testing.T) {
	for _, name := range []string{"source-binding", "record-expiry"} {
		t.Run(name, func(t *testing.T) {
			f := newAuditArchiveFixture(t, 4)
			if _, _, err := f.archive.persistTestPage(context.Background(), f.access, f.config.Source, archivePage(1)); err != nil {
				t.Fatal(err)
			}
			if name == "record-expiry" {
				if err := f.archive.store.exec("UPDATE archived_events SET expires=?1", named(1, sqliteUint(1101))); err != nil {
					t.Fatal(err)
				}
			}
			f.closeArchive()
			cfg := f.config
			if name == "source-binding" {
				cfg.Source.Generation++
			}
			charge, err := SQLiteAuditArchiveCharge(f.backing.limits, cfg)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := OpenSQLiteAuditArchive(context.Background(), f.backing, f.identity, f.continuity, cfg, f.reserve(charge, 1), f.environment)
			if archive != nil {
				f.stores = append(f.stores, archive.store)
			}
			if !errors.Is(err, ErrStorageFormat) {
				t.Fatal("unproven archive history accepted", err)
			}
		})
	}
}
func TestAuditArchiveSourceRevocationDuringDestinationCommitRollsBack(t *testing.T) {
	source := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 1000})
	_, wire := source.request(1, 1)
	if _, err := source.prepare(wire); err != nil {
		t.Fatal(err)
	}
	f := newAuditArchiveFixture(t, 4, source)
	sourceAccess := newAuditAccess(source, AuditOutboxExport)
	original := f.archive.store.execer
	f.archive.store.execer = &auditExecFault{ExecerContext: original, prefix: "INSERT INTO archived_events", after: func() error { sourceAccess.revoked.Store(true); return nil }}
	result, err := f.archive.TransferAuditPage(context.Background(), f.access, source.server, sourceAccess, auditQuery())
	if !errors.Is(err, ErrAuditDenied) || result.Acknowledgement != "not_started" || auditMetaForTest(t, source).ordinaryPending != 1 {
		t.Fatal("revoked source export committed/acknowledged", result, err)
	}
	f.archive.store.execer = original
	if f.count() != 0 {
		t.Fatal("source permission guard failed to roll back archive")
	}
}
