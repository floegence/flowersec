package ledgerv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"sync/atomic"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const sqliteAuditMetaSQL = `CREATE TABLE audit_meta (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=0), ordinary_count INTEGER NOT NULL CHECK(ordinary_count>=0), safety_count INTEGER NOT NULL CHECK(safety_count>=0), ordinary_pending INTEGER NOT NULL CHECK(ordinary_pending BETWEEN 0 AND ordinary_count), safety_pending INTEGER NOT NULL CHECK(safety_pending BETWEEN 0 AND safety_count)) STRICT, WITHOUT ROWID`
const sqliteAuditEventsSQL = `CREATE TABLE audit_events (revision INTEGER PRIMARY KEY CHECK(revision>0), event_id BLOB NOT NULL CHECK(length(event_id)=16), recorded BLOB NOT NULL CHECK(length(recorded)=8), expires BLOB NOT NULL CHECK(length(expires)=8), safety INTEGER NOT NULL CHECK(safety IN (0,1)), record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 512), exported INTEGER NOT NULL CHECK(exported IN (0,1))) STRICT, WITHOUT ROWID`

type sqliteAudit struct {
	store                               *sqliteStore
	clock                               *timev4.Clock
	policy                              SQLiteAuditPolicy
	tenant                              string
	object                              [16]byte
	rate                                auditRate
	denied, capacity, expiredUnexported atomic.Uint64
	wire                                [auditRecordBytes]byte
}

type auditMeta struct {
	revision                                         uint64
	ordinary, safety, ordinaryPending, safetyPending uint32
}

func (a *sqliteAudit) configure() error {
	if err := a.store.exec("PRAGMA secure_delete=ON"); err != nil {
		return err
	}
	v, err := a.store.scalar("PRAGMA secure_delete")
	if err != nil || v != int64(1) {
		return ErrStorageUnavailable
	}
	return nil
}

func (a *sqliteAudit) createSchema() error {
	for _, statement := range []string{sqliteAuditMetaSQL, sqliteAuditEventsSQL, "INSERT INTO audit_meta VALUES(1,0,0,0,0,0)"} {
		if err := a.store.exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func (a *sqliteAudit) verifySchema() error {
	for _, table := range []struct{ name, sql string }{{"audit_meta", sqliteAuditMetaSQL}, {"audit_events", sqliteAuditEventsSQL}} {
		size, err := a.store.scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || size != int64(len(table.sql)) {
			return ErrStorageFormat
		}
		ddl, err := a.store.scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='" + table.name + "'")
		if err != nil || ddl != table.sql {
			return ErrStorageFormat
		}
	}
	m, err := a.meta()
	if err != nil {
		return err
	}
	for _, check := range []struct {
		query    string
		expected uint32
	}{
		{"SELECT count(*) FROM audit_events WHERE safety=0", m.ordinary},
		{"SELECT count(*) FROM audit_events WHERE safety=1", m.safety},
		{"SELECT count(*) FROM audit_events WHERE safety=0 AND exported=0", m.ordinaryPending},
		{"SELECT count(*) FROM audit_events WHERE safety=1 AND exported=0", m.safetyPending},
	} {
		actual, err := a.store.scalar(check.query)
		if err != nil || actual != int64(check.expected) {
			return ErrStorageFormat
		}
	}
	invalid, err := a.store.scalar("SELECT count(*) FROM audit_events WHERE revision>?1 OR recorded>=expires", named(1, int64(m.revision)))
	if err != nil || invalid != int64(0) {
		return ErrStorageFormat
	}
	duplicates, err := a.store.scalar("SELECT count(*) FROM (SELECT event_id FROM audit_events GROUP BY event_id HAVING count(*)<>1)")
	if err != nil || duplicates != int64(0) {
		return ErrStorageFormat
	}
	// Decode bounded pages so restoring a file cannot introduce a different
	// tenant, object, actor or expiry than the exact configured transaction group.
	return a.validateRecords()
}

func (a *sqliteAudit) meta() (out auditMeta, err error) {
	err = a.store.readOne("SELECT revision,ordinary_count,safety_count,ordinary_pending,safety_pending FROM audit_meta WHERE id=1", 5, func(row []driver.Value) error {
		var numbers [5]int64
		for i := range numbers {
			v, ok := row[i].(int64)
			if !ok || v < 0 {
				return ErrStorageFormat
			}
			numbers[i] = v
		}
		if numbers[1] > int64(a.policy.OrdinaryRecords) || numbers[2] > int64(a.policy.SafetyRecords) || numbers[3] > numbers[1] || numbers[4] > numbers[2] || numbers[1]+numbers[2] > numbers[0] {
			return ErrStorageFormat
		}
		out = auditMeta{revision: uint64(numbers[0]), ordinary: uint32(numbers[1]), safety: uint32(numbers[2]), ordinaryPending: uint32(numbers[3]), safetyPending: uint32(numbers[4])}
		return nil
	})
	return
}

// append is callable only inside the original state's IMMEDIATE transaction.
// Record insertion and its revision/outbox accounting commit with that state;
// failure leaves no successful mutation with a missing mandatory audit record.
func (a *sqliteAudit) append(principal AuditPrincipal, action AuditAction, request [16]byte, beforeVersion, afterVersion uint64) error {
	if !principal.valid() || !action.valid() {
		return ErrAuditDenied
	}
	m, err := a.meta()
	if err != nil {
		return err
	}
	safety := action == AuditSourceRevoked
	if m.revision == math.MaxInt64 || !safety && m.ordinary >= a.policy.OrdinaryRecords || safety && m.safety >= a.policy.SafetyRecords {
		auditIncrement(&a.capacity, 1)
		return ErrAuditCapacity
	}
	now, err := a.clock.Sample()
	if err != nil || now.UpperMS == 0 || a.policy.RetentionMS > math.MaxUint64-now.UpperMS {
		return ErrAuditUnavailable
	}
	var eventID [16]byte
	if n, err := rand.Read(eventID[:]); err != nil || n != len(eventID) {
		// Audit event IDs are server-generated CSPRNG values. A failure must
		// close the audit append rather than inserting a predictable or partial ID.
		return ErrAuditUnavailable
	}
	record := AuditRecord{EventID: eventID, UTCMS: now.UpperMS, Principal: principal, Tenant: a.tenant, Action: action, Object: a.object, BeforeVersion: beforeVersion, AfterVersion: afterVersion, Request: request}
	n, err := EncodeAuditRecord(a.wire[:], record)
	if err != nil {
		return err
	}
	defer clear(a.wire[:])
	// One bounded scan refuses even a CSPRNG collision; it never overwrites or
	// lets a supplied identifier turn a fresh event into an export duplicate.
	existing, err := a.store.scalar("SELECT count(*) FROM audit_events WHERE event_id=?1", named(1, eventID[:]))
	if err != nil || existing != int64(0) {
		return ErrAuditUnavailable
	}
	class := int64(0)
	if safety {
		class = 1
	}
	if err = a.store.exec("INSERT INTO audit_events VALUES(?1,?2,?3,?4,?5,?6,0)", named(1, int64(m.revision+1)), named(2, eventID[:]), named(3, sqliteUint(record.UTCMS)), named(4, sqliteUint(record.UTCMS+a.policy.RetentionMS)), named(5, class), named(6, a.wire[:n])); err != nil {
		return err
	}
	if safety {
		m.safety++
		m.safetyPending++
	} else {
		m.ordinary++
		m.ordinaryPending++
	}
	if err = a.store.exec("UPDATE audit_meta SET revision=?1,ordinary_count=?2,safety_count=?3,ordinary_pending=?4,safety_pending=?5 WHERE id=1", named(1, int64(m.revision+1)), named(2, int64(m.ordinary)), named(3, int64(m.safety)), named(4, int64(m.ordinaryPending)), named(5, int64(m.safetyPending))); err != nil {
		return err
	}
	return a.store.changedOne()
}

func topUpAuditActor(access TopUpAccess, tenant string, source [16]byte) (AuditPrincipal, error) {
	audited, ok := access.(TopUpAuditAccess)
	if !ok {
		return AuditPrincipal{}, ErrAuditDenied
	}
	p, err := audited.TopUpAuditPrincipal(tenant, source)
	if err != nil || !p.valid() {
		return AuditPrincipal{}, ErrAuditDenied
	}
	return p, nil
}

func topUpAuditAction(before, after TopUpServerSnapshot) (AuditAction, bool) {
	switch {
	case !before.Permanent && after.Permanent:
		return AuditSourceRevoked, true
	case before.State != TopUpServerCommitted && after.State == TopUpServerCommitted:
		return AuditMaterialIssued, true
	// ACK and automatic expiry only converge the existing authoritative
	// operation. They cannot depend on admitting another ordinary audit row.
	case after.State == TopUpServerRetired:
		return 0, false
	case after.State == TopUpServerTerminal && (after.Terminal == protocolv4.V4TopUpErrorCodeTopUpRequestExpired || after.Terminal == protocolv4.V4TopUpErrorCodeSourceResetRequired):
		return 0, false
	case before.State != TopUpServerTerminal && after.State == TopUpServerTerminal:
		return AuditTopUpDenied, true
	case before.BindingGeneration != after.BindingGeneration:
		return AuditOwnerChanged, true
	default:
		return AuditTopUpPrepared, true
	}
}

func (a *sqliteAudit) authorize(access AuditAccess, permission AuditPermission) (AuditPrincipal, error) {
	if access == nil {
		auditIncrement(&a.denied, 1)
		return AuditPrincipal{}, ErrAuditDenied
	}
	p, err := access.CheckAuditAccess(a.store.identity, a.tenant, permission)
	if err != nil || !p.valid() {
		auditIncrement(&a.denied, 1)
		return AuditPrincipal{}, ErrAuditDenied
	}
	return p, nil
}

// beginRead does no database work until both the finite request gate and the
// separate management authorization pass. Store admission fixes concurrency at
// one actual synchronous operation with no waiting queue or helper goroutine.
func (j *SQLiteTopUpServer) beginAudit(ctx context.Context, access AuditAccess, permission AuditPermission) (*sqliteAudit, AuditPrincipal, error) {
	if j == nil || j.store == nil {
		return nil, AuditPrincipal{}, ErrAuditUnavailable
	}
	if err := j.store.begin(ctx); err != nil {
		return nil, AuditPrincipal{}, auditFailure(err)
	}
	a := j.audit
	if a == nil {
		j.store.end()
		return nil, AuditPrincipal{}, ErrAuditUnavailable
	}
	if err := a.rate.admit(a.clock, a.policy.ReadRequestsPerMinute, permission); err != nil {
		auditIncrement(&a.capacity, 1)
		j.store.end()
		return nil, AuditPrincipal{}, err
	}
	p, err := a.authorize(access, permission)
	if err != nil {
		j.store.end()
		return nil, AuditPrincipal{}, err
	}
	return a, p, nil
}

func (a *sqliteAudit) guard(ctx context.Context, access AuditAccess, permission AuditPermission, original AuditPrincipal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := a.authorize(access, permission)
	if err != nil || p != original {
		return ErrAuditDenied
	}
	if _, err := a.clock.Sample(); err != nil {
		return ErrAuditUnavailable
	}
	return a.store.checkFence()
}

func (a *sqliteAudit) pageCurrent(page AuditPage) error {
	now, err := a.clock.Sample()
	if err != nil {
		return ErrAuditUnavailable
	}
	for _, record := range page.Records[:page.Count] {
		if record.UTCMS > math.MaxUint64-a.policy.RetentionMS || !now.ValidBefore(record.UTCMS+a.policy.RetentionMS) {
			return ErrAuditUnavailable
		}
	}
	return nil
}

func (a *sqliteAudit) recordRow(row []driver.Value) (out AuditRecord, expiredAt uint64, exported bool, err error) {
	if len(row) != 7 {
		return out, 0, false, ErrStorageFormat
	}
	revision, rok := row[0].(int64)
	id, iok := row[1].([]byte)
	stamp, se := readSQLiteUint(row[2])
	expiry, ee := readSQLiteUint(row[3])
	safety, sok := row[4].(int64)
	blob, bok := row[5].([]byte)
	delivered, dok := row[6].(int64)
	if !rok || revision < 1 || !iok || len(id) != 16 || se != nil || ee != nil || !sok || safety < 0 || safety > 1 || !bok || len(blob) > auditRecordBytes || !dok || delivered < 0 || delivered > 1 {
		return out, 0, false, ErrStorageFormat
	}
	out, err = DecodeAuditRecord(blob)
	if err != nil || !bytes.Equal(id, out.EventID[:]) || out.UTCMS != stamp || stamp > math.MaxUint64-a.policy.RetentionMS || expiry != stamp+a.policy.RetentionMS || out.Tenant != a.tenant || out.Object != a.object || (safety == 1) != (out.Action == AuditSourceRevoked) {
		return AuditRecord{}, 0, false, ErrStorageFormat
	}
	return out, expiry, delivered == 1, nil
}

const auditRowColumns = "revision,CASE WHEN length(event_id)=16 THEN event_id ELSE NULL END,CASE WHEN length(recorded)=8 THEN recorded ELSE NULL END,CASE WHEN length(expires)=8 THEN expires ELSE NULL END,safety,CASE WHEN length(record)<=512 THEN record ELSE NULL END,exported"

func (a *sqliteAudit) validateRecords() (err error) {
	stored, err := a.store.scalar("SELECT CASE WHEN length(state_revision)=8 THEN state_revision ELSE NULL END FROM manifest WHERE id=1")
	if err != nil {
		return err
	}
	current, err := readSQLiteUint(stored)
	if err != nil {
		return err
	}
	rows, err := a.store.querier.QueryContext(context.Background(), "SELECT "+auditRowColumns+" FROM audit_events ORDER BY revision", nil)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	if len(rows.Columns()) != 7 {
		return ErrStorageFormat
	}
	var row [7]driver.Value
	var last uint64
	var lastVersion uint64
	for count := uint32(0); ; count++ {
		if err = rows.Next(row[:]); err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= a.policy.OrdinaryRecords+a.policy.SafetyRecords {
			return ErrStorageFormat
		}
		record, _, _, err := a.recordRow(row[:])
		sequence, ok := row[0].(int64)
		if err != nil || !ok || sequence < 1 || uint64(sequence) <= last || record.BeforeVersion < lastVersion || record.AfterVersion > current {
			return ErrStorageFormat
		}
		last = uint64(sequence)
		lastVersion = record.AfterVersion
		clear(row[:])
	}
}
