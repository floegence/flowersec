package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// These are independent management authentication fixtures, not production
// authentication providers or claims about deployment/storage qualification.
type auditAccessFixture struct {
	identity    SQLiteIdentity
	tenant      string
	permissions atomic.Uint32
	revoked     atomic.Bool
	role        atomic.Uint32
}

func newAuditAccess(f *topUpServerFixture, permissions ...AuditPermission) *auditAccessFixture {
	a := &auditAccessFixture{identity: f.identity, tenant: f.config.Tenant}
	a.role.Store(2)
	var mask uint32
	for _, permission := range permissions {
		mask |= 1 << permission
	}
	a.permissions.Store(mask)
	return a
}

func (a *auditAccessFixture) CheckAuditAccess(identity SQLiteIdentity, tenant string, permission AuditPermission) (AuditPrincipal, error) {
	if a.revoked.Load() || identity != a.identity || tenant != a.tenant || a.permissions.Load()&(1<<permission) == 0 {
		return AuditPrincipal{}, errors.New("private authentication rejection")
	}
	return AuditPrincipal{Actor: [32]byte{77}, Role: uint16(a.role.Load())}, nil
}

func auditQuery() AuditQuery {
	return AuditQuery{UntilMS: 10000, Limit: AuditPageRecords, OutputBytes: AuditPageBytes}
}

func auditMetaForTest(t *testing.T, f *topUpServerFixture) auditMeta {
	t.Helper()
	m, err := f.server.audit.meta()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type auditExecFault struct {
	driver.ExecerContext
	prefix        string
	before, after func() error
}

func (f *auditExecFault) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	match := strings.HasPrefix(query, f.prefix)
	if match && f.before != nil {
		if err := f.before(); err != nil {
			return nil, err
		}
	}
	result, err := f.ExecerContext.ExecContext(ctx, query, args)
	if err == nil && match && f.after != nil {
		err = f.after()
	}
	return result, err
}

type auditQueryFault struct {
	driver.QueryerContext
	calls atomic.Uint32
	after func(string)
}

func (f *auditQueryFault) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f.calls.Add(1)
	rows, err := f.QueryerContext.QueryContext(ctx, query, args)
	if err == nil && f.after != nil {
		f.after(query)
	}
	return rows, err
}

func TestSQLiteAuditStateCommitAtomicReplayAndUnknown(t *testing.T) {
	f := newTopUpServerFixture(t)
	r, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	before := f.state()
	meta := auditMetaForTest(t, f)
	if meta.revision != 1 || meta.ordinary != 1 || auditSourceRevisionForTest(t, f) != 1 {
		t.Fatal(meta, before)
	}
	response, _ := serverTopUpResponse(t, r, 1, false, 0)
	original := f.server.store.execer
	f.server.store.execer = &auditExecFault{ExecerContext: original, prefix: "INSERT INTO audit_events", before: func() error { return errors.New("disk full with private details") }}
	if _, err := f.server.Commit(context.Background(), f.authority, wire, response); err == nil {
		t.Fatal("grant committed without audit storage")
	}
	f.server.store.execer = original
	if after := f.state(); after != before || auditMetaForTest(t, f) != meta {
		t.Fatal("audit failure did not roll back original authority", after)
	}
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost acknowledgement") }}
	fault.commits.Store(1)
	f.server.store.execer = fault
	if _, err := f.server.Commit(context.Background(), f.authority, wire, response); !errors.Is(err, ErrUnknown) {
		t.Fatal("ambiguous commit became a success/rollback fact", err)
	}
	f.server.store.execer = original
	if got := f.state(); got.State != TopUpServerCommitted || auditSourceRevisionForTest(t, f) != 2 {
		t.Fatal(got)
	}
	exporter := newAuditAccess(f, AuditOutboxExport)
	page, err := f.server.ExportAudit(context.Background(), exporter, auditQuery())
	if err != nil || page.Count != 2 || !page.Complete || page.ThroughSequence != 2 {
		t.Fatal(page.Count, err)
	}
	issued := page.Records[1]
	if issued.Action != AuditMaterialIssued || issued.Request != r.Operation || issued.BeforeVersion != 1 || issued.AfterVersion != 2 || issued.Principal.Actor != ([32]byte{5}) || issued.Tenant != f.config.Tenant || issued.Object != f.config.Source || issued.EventID == page.Records[0].EventID {
		t.Fatal("audit did not bind original actor/change", issued.Action, issued.BeforeVersion, issued.AfterVersion)
	}
	if _, err := f.server.Commit(context.Background(), f.authority, wire, response); err != nil {
		t.Fatal(err)
	}
	if result, err := f.prepare(wire); err != nil || !result.Replay {
		t.Fatal(result, err)
	}
	if got := auditMetaForTest(t, f); got.revision != 2 || got.ordinary != 2 {
		t.Fatal("replay duplicated audit", got)
	}
	closeSQLite(t, f.server.store)
	f.openServer(false)
	restored, err := f.server.ExportAudit(context.Background(), exporter, auditQuery())
	if err != nil || restored != page {
		t.Fatal("reopen regenerated audit identifiers or state", err)
	}
}

func TestSQLiteAuditOrdinaryCapacityReservesSafetyAndExport(t *testing.T) {
	f := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{OrdinaryRecords: 1, SafetyRecords: 1})
	r, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	before := f.state()
	response, _ := serverTopUpResponse(t, r, 1, false, 0)
	if _, err := f.server.Commit(context.Background(), f.authority, wire, response); !errors.Is(err, ErrAuditCapacity) {
		t.Fatal(err)
	}
	if f.state() != before {
		t.Fatal("full ordinary audit admitted expansion")
	}
	f.authority.commitGate.Lock()
	f.authority.permanent.Store(true)
	f.authority.commitGate.Unlock()
	fenced, err := f.server.AdvanceRetirement(context.Background(), f.authority)
	if err != nil || !fenced.Permanent || fenced.State != TopUpServerRetired {
		t.Fatal(fenced, err)
	}
	m := auditMetaForTest(t, f)
	if m.ordinary != 1 || m.safety != 1 || m.revision != 2 {
		t.Fatal("ordinary records used safety reserve", m)
	}
	if _, err := f.prepare(wire); !topUpIsFailure(err, protocolv4.V4TopUpErrorCodeSourceResetRequired) {
		t.Fatal("revoked source reopened", err)
	}
	exporter := newAuditAccess(f, AuditOutboxExport)
	page, err := f.server.ExportAudit(context.Background(), exporter, auditQuery())
	if err != nil || page.Count != 2 || page.Records[1].Action != AuditSourceRevoked {
		t.Fatal("full audit deadlocked export", page.Count, err)
	}
	var receipts [2]AuditExportReceipt
	for i := range receipts {
		receipts[i] = AuditExportReceipt{Sequence: page.Sequences[i], EventID: page.Records[i].EventID}
	}
	for range 2 {
		if err := f.server.AcknowledgeAuditExport(context.Background(), exporter, receipts[:]); err != nil {
			t.Fatal("exact export ACK not idempotent", err)
		}
	}
	m = auditMetaForTest(t, f)
	if m.ordinary != 1 || m.safety != 1 || m.ordinaryPending != 0 || m.safetyPending != 0 {
		t.Fatal("ack erased retained facts or double-counted pending", m)
	}
	reader := newAuditAccess(f, AuditRecordsRead, AuditAuthorizationRead)
	if page, err := f.server.ReadAudit(context.Background(), reader, auditQuery()); !errors.Is(err, ErrAuditCapacity) || page.Count != 0 {
		t.Fatal("sensitive read escaped missing mandatory audit", page.Count, err)
	}
	if state, err := f.server.ReadAuthorization(context.Background(), reader); !errors.Is(err, ErrAuditCapacity) || state != (TopUpServerSnapshot{}) {
		t.Fatal(state, err)
	}
}

func TestSQLiteAuditCapacityDoesNotDelayExpiryOrAck(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		f := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{OrdinaryRecords: 1, SafetyRecords: 1})
		_, wire := f.request(1, 1)
		if _, err := f.prepare(wire); err != nil {
			t.Fatal(err)
		}
		f.tick.Store(410)
		terminal, err := f.prepare(wire)
		if err != nil || terminal.Snapshot.State != TopUpServerTerminal || terminal.Snapshot.Terminal != protocolv4.V4TopUpErrorCodeTopUpRequestExpired {
			t.Fatal(terminal, err)
		}
		retired, err := f.server.AdvanceRetirement(context.Background(), f.authority)
		if err != nil || retired.State != TopUpServerRetired || auditSourceRevisionForTest(t, f) != 3 {
			t.Fatal(retired, err)
		}
		if got := auditMetaForTest(t, f); got.ordinary != 1 {
			t.Fatal("expiry required new audit capacity", got)
		}
	})
	t.Run("ack", func(t *testing.T) {
		f := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{OrdinaryRecords: 2, SafetyRecords: 1})
		r, wire := f.request(1, 1)
		if _, err := f.prepare(wire); err != nil {
			t.Fatal(err)
		}
		response, facts := serverTopUpResponse(t, r, 1, false, 0)
		if _, err := f.server.Commit(context.Background(), f.authority, wire, response); err != nil {
			t.Fatal(err)
		}
		state, err := f.server.Ack(context.Background(), f.authority, serverTopUpAck(t, r, facts, 1))
		if err != nil || state.State != TopUpServerRetired {
			t.Fatal("audit blocked original ACK cleanup", state, err)
		}
	})
}

func TestSQLiteAuditFailureCannotReopenVerifiedSourceFence(t *testing.T) {
	f := newTopUpServerFixture(t)
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	f.authority.permanent.Store(true)
	original := f.server.store.execer
	f.server.store.execer = &auditExecFault{ExecerContext: original, prefix: "INSERT INTO audit_events", before: func() error { return errors.New("safety storage failure") }}
	if _, err := f.server.AdvanceRetirement(context.Background(), f.authority); err == nil {
		t.Fatal("claimed durable safety audit after failure")
	}
	f.server.store.execer = original
	if _, err := f.prepare(wire); !topUpIsFailure(err, protocolv4.V4TopUpErrorCodeSourceResetRequired) {
		t.Fatal("audit failure postponed verified source fence", err)
	}
	if got := auditMetaForTest(t, f); got.safety != 0 {
		t.Fatal("failed transaction invented safety fact", got)
	}
}

func TestSQLiteAuditPermissionsPrecedeQueriesAndHaveSeparateRateCapacity(t *testing.T) {
	f := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{ReadRequestsPerMinute: 3})
	reader := newAuditAccess(f)
	original := f.server.store.querier
	spy := &auditQueryFault{QueryerContext: original}
	f.server.store.querier = spy
	if _, err := f.server.ReadAudit(context.Background(), reader, auditQuery()); !errors.Is(err, ErrAuditDenied) || spy.calls.Load() != 0 {
		t.Fatal("unauthorized query reached storage", err, spy.calls.Load())
	}
	reader.permissions.Store(1 << AuditOperationsRead)
	if _, err := f.server.AuditStatus(context.Background(), reader); err != nil {
		t.Fatal(err)
	}
	queries := spy.calls.Load()
	if _, err := f.server.ReadAuthorization(context.Background(), reader); !errors.Is(err, ErrAuditDenied) || spy.calls.Load() != queries {
		t.Fatal("operations permission implied sensitive read", err)
	}
	if _, err := f.server.AuditStatus(context.Background(), reader); !errors.Is(err, ErrAuditCapacity) {
		t.Fatal("read rate not enforced", err)
	}
	f.server.store.querier = original
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal("read flood consumed mutation audit reserve", err)
	}
	exporter := newAuditAccess(f, AuditOutboxExport)
	if page, err := f.server.ExportAudit(context.Background(), exporter, auditQuery()); err != nil || page.Count != 1 {
		t.Fatal("ordinary read quota blocked outbox drain", page.Count, err)
	}
	f.tick.Store(60000)
	if status, err := f.server.AuditStatus(context.Background(), reader); err != nil || status.Denied != 2 || status.CapacityRejected == 0 {
		t.Fatal(status, err)
	}
}

func TestSQLiteAuditCrossTenantAndIndependentPermissions(t *testing.T) {
	f := newTopUpServerFixture(t)
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	wrongTenant := newAuditAccess(f, AuditRecordsRead, AuditAuthorizationRead, AuditOutboxExport)
	wrongTenant.tenant = "another-tenant"
	if _, err := f.server.ExportAudit(context.Background(), wrongTenant, auditQuery()); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("cross-tenant audit export", err)
	}
	wrongDeployment := newAuditAccess(f, AuditRecordsRead)
	wrongDeployment.identity.StoreID = [32]byte{99}
	if _, err := f.server.ReadAudit(context.Background(), wrongDeployment, auditQuery()); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("cross-deployment audit read", err)
	}
	reader := newAuditAccess(f, AuditRecordsRead)
	if err := f.server.ExpireAudit(context.Background(), reader); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("read permission deleted audit", err)
	}
	if err := f.server.AcknowledgeAuditExport(context.Background(), reader, nil); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("read permission changed delivery state", err)
	}
}

func TestSQLiteAuditLateRevocationSuppressesOutputAndRollsBackReadRecord(t *testing.T) {
	for _, action := range []string{"revoke", "change_actor_role"} {
		t.Run(action, func(t *testing.T) {
			f := newTopUpServerFixture(t)
			_, wire := f.request(1, 1)
			if _, err := f.prepare(wire); err != nil {
				t.Fatal(err)
			}
			reader := newAuditAccess(f, AuditAuthorizationRead)
			before := auditMetaForTest(t, f)
			original := f.server.store.execer
			f.server.store.execer = &auditExecFault{ExecerContext: original, prefix: "INSERT INTO audit_events", after: func() error {
				if action == "revoke" {
					reader.revoked.Store(true)
				} else {
					reader.role.Store(3)
				}
				return nil
			}}
			state, err := f.server.ReadAuthorization(context.Background(), reader)
			f.server.store.execer = original
			if !errors.Is(err, ErrAuditDenied) || state != (TopUpServerSnapshot{}) || auditMetaForTest(t, f) != before {
				t.Fatal("late permission change exposed a record", err)
			}
		})
	}
}

func TestSQLiteAuditPaginationHasFixedBoundaryAndOutputCap(t *testing.T) {
	f := newTopUpServerFixture(t)
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	reader := newAuditAccess(f, AuditAuthorizationRead, AuditRecordsRead)
	for range 6 {
		if _, err := f.server.ReadAuthorization(context.Background(), reader); err != nil {
			t.Fatal(err)
		}
	}
	q := auditQuery()
	q.Limit, q.OutputBytes = 2, 512
	var sequences []uint64
	var firstEvent AuditRecord
	for pages := 0; ; pages++ {
		if pages >= 5 {
			t.Fatal("auditing a read extended its own pagination")
		}
		page, err := f.server.ReadAudit(context.Background(), reader, q)
		if err != nil || page.ThroughSequence != 7 || page.Count > 2 || page.EncodedBytes > 512 {
			t.Fatal(page.Count, page.ThroughSequence, err)
		}
		encoded := make([]byte, page.EncodedBytes)
		n, err := EncodeAuditPage(encoded, page)
		if err != nil || uint32(n) != page.EncodedBytes || binary.BigEndian.Uint64(encoded[:8]) != uint64(page.Count) || binary.BigEndian.Uint64(encoded[16:24]) != 7 {
			t.Fatal("controlled output ceiling/metadata mismatch", n, err)
		}
		for i := range int(page.Count) {
			sequences = append(sequences, page.Sequences[i])
		}
		if pages == 0 {
			firstEvent = page.Records[0]
		}
		q.AfterSequence, q.ThroughSequence = page.NextSequence, page.ThroughSequence
		if page.Complete {
			break
		}
	}
	if len(sequences) != 7 {
		t.Fatal(sequences)
	}
	for i, sequence := range sequences {
		if sequence != uint64(i+1) {
			t.Fatal("pagination lost/duplicated original records", sequences)
		}
	}
	if fmt.Sprintf("%+v %#v", firstEvent, firstEvent) != "Flowersec.AuditRecord Flowersec.AuditRecord" {
		t.Fatal("audit identity escaped ordinary formatting")
	}
	encoded, err := json.Marshal(firstEvent)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("audit fields entered ordinary JSON", string(encoded), err)
	}
}

func TestSQLiteAuditRetentionDeletesActualBytesAndNeverResetsSequence(t *testing.T) {
	f := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 100})
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	access := newAuditAccess(f, AuditOutboxExport, AuditRetentionMaintenance, AuditOperationsRead)
	page, err := f.server.ExportAudit(context.Background(), access, auditQuery())
	if err != nil || page.Count != 1 {
		t.Fatal(page.Count, err)
	}
	id := page.Records[0].EventID
	f.tick.Store(99)
	if err := f.server.ExpireAudit(context.Background(), access); err != nil {
		t.Fatal(err)
	}
	if auditMetaForTest(t, f).ordinary != 1 {
		t.Fatal("retention deleted before original lower-bound deadline")
	}
	f.tick.Store(100)
	if err := f.server.ExpireAudit(context.Background(), access); err != nil {
		t.Fatal(err)
	}
	m := auditMetaForTest(t, f)
	if m.ordinary != 0 || m.ordinaryPending != 0 || m.revision != 1 {
		t.Fatal("deletion reset durable event sequence", m)
	}
	status, err := f.server.AuditStatus(context.Background(), access)
	if err != nil || status.ExpiredUnexported != 1 {
		t.Fatal(status, err)
	}
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(f.backing.path + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, id[:]) {
			t.Fatal("expired record survived in live database/WAL", suffix)
		}
	}
	closeSQLite(t, f.server.store)
	f.openServer(false)
	page, err = f.server.ExportAudit(context.Background(), access, auditQuery())
	if err != nil || page.Count != 0 || page.NextSequence != 1 || !page.Complete {
		t.Fatal("expiry did not survive reopen", page.Count, err)
	}
}

func TestSQLiteAuditExportDoesNotPublishRowsThatExpireDuringRead(t *testing.T) {
	f := newTopUpServerFixtureWithAudit(t, SQLiteAuditPolicy{RetentionMS: 100})
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	exporter := newAuditAccess(f, AuditOutboxExport)
	original := f.server.store.querier
	f.server.store.querier = &auditQueryFault{QueryerContext: original, after: func(query string) {
		if strings.Contains(query, "FROM audit_events WHERE revision>") {
			f.tick.Store(100)
		}
	}}
	page, err := f.server.ExportAudit(context.Background(), exporter, auditQuery())
	f.server.store.querier = original
	if !errors.Is(err, ErrAuditUnavailable) || page != (AuditPage{}) {
		t.Fatal("expired export survived final check", page.Count, err)
	}
}

func TestSQLiteAuditExactSchemaPolicyAndCorruptRowsAreRejected(t *testing.T) {
	for _, name := range []string{"policy", "row", "counts", "future_version"} {
		t.Run(name, func(t *testing.T) {
			f := newTopUpServerFixture(t)
			_, wire := f.request(1, 1)
			if _, err := f.prepare(wire); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "policy":
				f.config.Audit.RetentionMS = 100
			case "row":
				if err := f.server.store.exec("UPDATE audit_events SET record=x'00'"); err != nil {
					t.Fatal(err)
				}
			case "counts":
				if err := f.server.store.exec("UPDATE audit_meta SET ordinary_pending=0"); err != nil {
					t.Fatal(err)
				}
			case "future_version":
				if err := f.server.store.exec("UPDATE manifest SET state_revision=?1", named(1, sqliteUint(0))); err != nil {
					t.Fatal(err)
				}
			}
			closeSQLite(t, f.server.store)
			charge, err := SQLiteTopUpServerCharge(f.backing.limits, f.config)
			if err != nil {
				t.Fatal(err)
			}
			server, err := OpenSQLiteTopUpServer(context.Background(), f.backing, f.identity, f.continuity, f.config, f.reserve(charge, 1), f.environment)
			if server != nil {
				f.stores = append(f.stores, server.store)
			}
			if !errors.Is(err, ErrStorageFormat) {
				t.Fatal("inconsistent audit reopened", name, err)
			}
		})
	}
}

func auditSourceRevisionForTest(t *testing.T, f *topUpServerFixture) uint64 {
	t.Helper()
	revision, err := f.server.stateRevision()
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

type sourceAccessWithoutActor struct{ TopUpAccess }

func TestSQLiteAuditCriticalMutationRequiresOriginalActorAndFiniteVersions(t *testing.T) {
	f := newTopUpServerFixture(t)
	r, wire := f.request(1, 1)
	if _, err := f.server.Prepare(context.Background(), sourceAccessWithoutActor{f.authority}, wire, f.dst); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("unsigned/missing actor accepted", err)
	}
	if got := f.state(); got.State != TopUpServerEmpty || auditSourceRevisionForTest(t, f) != 0 || auditMetaForTest(t, f).revision != 0 {
		t.Fatal("missing actor changed authority", got)
	}
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	if err := f.server.store.exec("UPDATE manifest SET state_revision=?1", named(1, sqliteUint(math.MaxUint64))); err != nil {
		t.Fatal(err)
	}
	response, _ := serverTopUpResponse(t, r, 1, false, 0)
	if _, err := f.server.Commit(context.Background(), f.authority, wire, response); !errors.Is(err, ErrCapacity) {
		t.Fatal("local version wrapped", err)
	}
	if auditSourceRevisionForTest(t, f) != math.MaxUint64 || auditMetaForTest(t, f).revision != 1 || f.state().State != TopUpServerPending {
		t.Fatal("overflow advanced authority/audit")
	}
}

func TestSQLiteAuditQueriesCannotExpandWindowPageOrProjection(t *testing.T) {
	f := newTopUpServerFixture(t)
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	reader := newAuditAccess(f, AuditRecordsRead)
	before := auditMetaForTest(t, f)
	for _, mutate := range []func(*AuditQuery){
		func(q *AuditQuery) { q.UntilMS = auditDayMS + 1 },
		func(q *AuditQuery) { q.FromMS = q.UntilMS },
		func(q *AuditQuery) { q.Limit = AuditPageRecords + 1 },
		func(q *AuditQuery) { q.OutputBytes = AuditPageBytes + 1 },
		func(q *AuditQuery) { q.OutputBytes = 1 },
		func(q *AuditQuery) { q.AfterSequence = math.MaxUint64 },
		func(q *AuditQuery) { q.AfterSequence = 2; q.ThroughSequence = 1 },
		func(q *AuditQuery) { q.ThroughSequence = 2 },
	} {
		q := auditQuery()
		mutate(&q)
		if page, err := f.server.ReadAudit(context.Background(), reader, q); err == nil || page != (AuditPage{}) {
			t.Fatal("unbounded/invalid query accepted", q, err)
		}
		if auditMetaForTest(t, f) != before {
			t.Fatal("invalid query consumed mandatory audit storage")
		}
	}
}

func TestSQLiteAuditReadUnknownCommitIsOpaqueAndKeepsOriginalRecord(t *testing.T) {
	f := newTopUpServerFixture(t)
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	reader := newAuditAccess(f, AuditAuthorizationRead)
	original := f.server.store.execer
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("private actor https://secret-endpoint payload") }}
	fault.commits.Store(1)
	f.server.store.execer = fault
	state, err := f.server.ReadAuthorization(context.Background(), reader)
	f.server.store.execer = original
	if err != ErrAuditUnknown || errors.Unwrap(err) != nil || state != (TopUpServerSnapshot{}) {
		t.Fatal("audit error disclosed raw details or invented result", err)
	}
	if got := auditMetaForTest(t, f); got.revision != 2 || got.ordinaryPending != 2 {
		t.Fatal("unknown read commit erased durable audit", got)
	}
}

func TestSQLiteAuditCloseKeepsActualProviderTailAndReadConcurrencyBound(t *testing.T) {
	f := newTopUpServerFixture(t)
	_, wire := f.request(1, 1)
	if _, err := f.prepare(wire); err != nil {
		t.Fatal(err)
	}
	reader := newAuditAccess(f, AuditRecordsRead, AuditOperationsRead)
	original := f.server.store.execer
	fault := &topUpServerCommitTail{ExecerContext: original, entered: make(chan struct{}), release: make(chan struct{})}
	f.server.store.execer = fault
	done := make(chan error, 1)
	go func() { _, err := f.server.ReadAudit(context.Background(), reader, auditQuery()); done <- err }()
	select {
	case <-fault.entered:
	case <-time.After(5 * time.Second):
		close(fault.release)
		t.Fatal("audit read did not enter provider")
	}
	if _, err := f.server.AuditStatus(context.Background(), reader); !errors.Is(err, ErrAuditCapacity) {
		close(fault.release)
		<-done
		t.Fatal("second read borrowed a new provider slot", err)
	}
	before := f.root.Snapshot().Charged
	f.server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.server.WaitCleanup(ctx); err == nil || f.root.Snapshot().Charged != before {
		close(fault.release)
		<-done
		t.Fatal("close refunded real audit provider tail", err)
	}
	close(fault.release)
	if err := <-done; err != ErrAuditUnknown {
		t.Fatal(err)
	}
	if err := f.server.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOperationsStoreGuardDoesNotQueryOrGrantOtherPermissions(t *testing.T) {
	f := newTopUpServerFixture(t)
	access := newAuditAccess(f, AuditOperationsRead)
	fault := &auditQueryFault{QueryerContext: f.server.store.querier}
	f.server.store.querier = fault
	for range 3 {
		principal, err := f.server.OperationsAuthorization(access)
		if err != nil || principal.Actor != [32]byte{77} {
			t.Fatal("original management reader not authorized", err)
		}
	}
	if fault.calls.Load() != 0 {
		t.Fatal("output guard queried storage")
	}
	if _, err := f.server.ReadAuthorization(context.Background(), access); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("aggregate permission granted sensitive read", err)
	}
	access.revoked.Store(true)
	if _, err := f.server.OperationsAuthorization(access); !errors.Is(err, ErrAuditDenied) {
		t.Fatal("revoked management reader retained authority", err)
	}
}
