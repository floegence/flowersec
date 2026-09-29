package ledgerv4

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// AuditMaintenanceHarness uses two actual stores in the same root/Environment.
// Independent authority, authorization and restore proofs are test fixtures.
type AuditMaintenanceHarness struct {
	source                      *topUpServerFixture
	archiveAccess               *auditAccessFixture
	Source                      *SQLiteTopUpServer
	Archive                     *SQLiteAuditArchive
	SourceAccess, ArchiveAccess AuditAccess
	Root                        *resourcev4.Root
	Clock                       *timev4.Clock
}

func NewAuditMaintenanceHarness(t *testing.T) *AuditMaintenanceHarness {
	t.Helper()
	source := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 1000})
	path := filepath.Join(t.TempDir(), "audit-archive.db")
	limits := SQLiteLimits{MaxPages: 64, MaxRecords: 4, MaxRecordBytes: 1024, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	cost, err := SQLiteBackingCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	backing, err := NewSQLiteBacking(path, limits, source.reserve(cost, 1), source.environment)
	if err != nil {
		t.Fatal(err)
	}
	identity := SQLiteIdentity{Authority: "archive.test", StoreID: [32]byte{17}, Generation: 1}
	continuity := sqliteContinuityFunc(func(got SQLiteIdentity, _ uint64, _ bool) error {
		if got != identity {
			return ErrFenced
		}
		return nil
	})
	config := SQLiteAuditArchiveConfig{Source: source.identity, Tenant: source.config.Tenant, Object: source.config.Source, Records: 4, RetentionMS: 1000, RequestsPerMinute: 60, Clock: source.clock}
	cost, err = SQLiteAuditArchiveCharge(limits, config)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := CreateSQLiteAuditArchive(context.Background(), backing, identity, continuity, config, source.reserve(cost, 1), source.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		archive.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := archive.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := archive.Retire(); err != nil {
			t.Error(err)
			return
		}
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
	access := &auditAccessFixture{identity: identity, tenant: config.Tenant}
	access.role.Store(2)
	access.permissions.Store(1<<AuditOutboxExport | 1<<AuditRetentionMaintenance | 1<<AuditOperationsRead)
	sourceAccess := newAuditAccess(source, AuditOutboxExport, AuditRetentionMaintenance, AuditOperationsRead)
	return &AuditMaintenanceHarness{source: source, archiveAccess: access, Source: source.server, Archive: archive, SourceAccess: sourceAccess, ArchiveAccess: access, Root: source.root, Clock: source.clock}
}
func (h *AuditMaintenanceHarness) Reserve(cost resourcev4.Vector) resourcev4.Reference {
	return h.source.reserve(cost, 1)
}
func (h *AuditMaintenanceHarness) Prepare(t *testing.T) {
	t.Helper()
	_, wire := h.source.request(1, 1)
	if _, err := h.source.prepare(wire); err != nil {
		t.Fatal(err)
	}
}
func (h *AuditMaintenanceHarness) Tick(tick uint64) { h.source.tick.Store(tick) }
func (h *AuditMaintenanceHarness) RevokeArchive()   { h.archiveAccess.revoked.Store(true) }
func (h *AuditMaintenanceHarness) BlockArchiveCommit() (entered <-chan struct{}, release func()) {
	fault := &topUpServerCommitTail{ExecerContext: h.Archive.store.execer, entered: make(chan struct{}), release: make(chan struct{})}
	h.Archive.store.execer = fault
	return fault.entered, func() { close(fault.release) }
}
