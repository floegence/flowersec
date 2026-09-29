package ledgerv4

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

// AuditStatus is the fixed aggregate operations view of this transaction group.
// It cannot mutate protocol state or expose source credentials/actor records.
func (j *SQLiteTopUpServer) AuditStatus(ctx context.Context, access AuditAccess) (AuditStatus, error) {
	a, principal, err := j.beginAudit(ctx, access, AuditOperationsRead)
	if err != nil {
		return AuditStatus{}, err
	}
	defer j.store.end()
	if err = a.guard(ctx, access, AuditOperationsRead, principal); err != nil {
		return AuditStatus{}, auditFailure(err)
	}
	m, err := a.meta()
	if err != nil {
		return AuditStatus{}, auditFailure(err)
	}
	now, err := a.clock.Sample()
	if err != nil {
		return AuditStatus{}, ErrAuditUnavailable
	}
	if err = a.guard(ctx, access, AuditOperationsRead, principal); err != nil {
		return AuditStatus{}, auditFailure(err)
	}
	return AuditStatus{Policy: a.policy, Sequence: m.revision, OrdinaryRecords: m.ordinary, SafetyRecords: m.safety, OrdinaryPending: m.ordinaryPending, SafetyPending: m.safetyPending, ObservedUTCMS: now.UpperMS, Denied: a.denied.Load(), CapacityRejected: a.capacity.Load(), ExpiredUnexported: a.expiredUnexported.Load()}, nil
}

// ReadAuthorization is a separately authorized sensitive-record query. It
// exposes bounded facts, never the canonical response's credential material.
// The allowed read is durably audited before any value is returned.
func (j *SQLiteTopUpServer) ReadAuthorization(ctx context.Context, access AuditAccess) (TopUpServerSnapshot, error) {
	a, principal, err := j.beginAudit(ctx, access, AuditAuthorizationRead)
	if err != nil {
		return TopUpServerSnapshot{}, err
	}
	defer j.store.end()
	guard := func() error { return a.guard(ctx, access, AuditAuthorizationRead, principal) }
	var result TopUpServerSnapshot
	err = j.store.writeTransaction(ctx, guard, func() error {
		var err error
		result, err = j.readState()
		if err != nil {
			return err
		}
		revision, err := j.stateRevision()
		if err != nil {
			return err
		}
		return a.append(principal, AuditAuthorizationObserved, [16]byte{}, revision, revision)
	})
	if err == nil {
		err = guard()
	}
	if err != nil {
		return TopUpServerSnapshot{}, auditFailure(err)
	}
	return result, nil
}

// ReadAudit has a fixed tenant/object scope, a one-day query window, at most 16
// records and at most 8192 encoded output bytes. There is no projection or SQL
// expression parameter. Ordinary audit readers cannot acknowledge or delete.
func (j *SQLiteTopUpServer) ReadAudit(ctx context.Context, access AuditAccess, query AuditQuery) (AuditPage, error) {
	a, principal, err := j.beginAudit(ctx, access, AuditRecordsRead)
	if err != nil {
		return AuditPage{}, err
	}
	defer j.store.end()
	if !query.valid() {
		return AuditPage{}, ErrAuditUnavailable
	}
	guard := func() error { return a.guard(ctx, access, AuditRecordsRead, principal) }
	var page AuditPage
	err = j.store.writeTransaction(ctx, guard, func() error {
		var err error
		page, err = a.page(query, false)
		if err != nil {
			return err
		}
		revision, err := j.stateRevision()
		if err != nil {
			return err
		}
		return a.append(principal, AuditRecordsObserved, [16]byte{}, revision, revision)
	})
	if err == nil {
		err = guard()
	}
	if err != nil {
		return AuditPage{}, auditFailure(err)
	}
	if err = a.pageCurrent(page); err != nil {
		return AuditPage{}, err
	}
	return page, nil
}

// ExportAudit is the deployment exporter's fixed outbox transfer, separately
// authorized from interactive audit reading. Repeated transfer returns the same
// event IDs. Internal outbox transfer does not append recursive read events and
// therefore still drains when ordinary audit storage is full. A supported
// exporter must persist/deduplicate by EventID and implement its own tested TTL.
func (j *SQLiteTopUpServer) ExportAudit(ctx context.Context, access AuditAccess, query AuditQuery) (AuditPage, error) {
	a, principal, err := j.beginAudit(ctx, access, AuditOutboxExport)
	if err != nil {
		return AuditPage{}, err
	}
	defer j.store.end()
	if !query.valid() {
		return AuditPage{}, ErrAuditUnavailable
	}
	if err = a.guard(ctx, access, AuditOutboxExport, principal); err != nil {
		return AuditPage{}, auditFailure(err)
	}
	page, err := a.page(query, true)
	if err == nil {
		err = a.guard(ctx, access, AuditOutboxExport, principal)
	}
	if err != nil {
		return AuditPage{}, auditFailure(err)
	}
	if err = a.pageCurrent(page); err != nil {
		return AuditPage{}, err
	}
	return page, nil
}

func (a *sqliteAudit) page(query AuditQuery, pending bool) (out AuditPage, err error) {
	now, err := a.clock.Sample()
	if err != nil {
		return out, err
	}
	m, err := a.meta()
	if err != nil {
		return out, err
	}
	through := query.ThroughSequence
	if through == 0 {
		through = m.revision
	}
	if through > m.revision || query.AfterSequence > through {
		return out, ErrConfiguration
	}
	statement := "SELECT " + auditRowColumns + " FROM audit_events WHERE revision>?1 AND recorded>=?2 AND recorded<?3 AND expires>?4 AND revision<=?6"
	if pending {
		statement += " AND exported=0"
	}
	statement += " ORDER BY revision LIMIT ?5"
	rows, err := a.store.querier.QueryContext(context.Background(), statement, []driver.NamedValue{named(1, int64(query.AfterSequence)), named(2, sqliteUint(query.FromMS)), named(3, sqliteUint(query.UntilMS)), named(4, sqliteUint(now.UpperMS)), named(5, int64(query.Limit)+1), named(6, int64(through))})
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	if len(rows.Columns()) != 7 {
		return out, ErrStorageFormat
	}
	out.NextSequence, out.ThroughSequence, out.EncodedBytes = query.AfterSequence, through, 32
	var row [7]driver.Value
	for {
		if err = rows.Next(row[:]); err == io.EOF {
			out.Complete, out.NextSequence = true, through
			return out, nil
		}
		if err != nil {
			return AuditPage{}, err
		}
		if out.Count >= query.Limit {
			return out, nil
		}
		record, _, exported, err := a.recordRow(row[:])
		if err != nil || uint64(row[0].(int64)) <= out.NextSequence || pending && exported {
			return AuditPage{}, ErrStorageFormat
		}
		blob := row[5].([]byte)
		if uint64(out.EncodedBytes)+uint64(len(blob))+10 > uint64(query.OutputBytes) {
			if out.Count == 0 {
				// A page must make progress or report a bounded capacity
				// failure. Returning the same cursor with Complete=false
				// would make a caller spin forever on one oversized record.
				return AuditPage{}, ErrAuditCapacity
			}
			return out, nil
		}
		out.Records[out.Count] = record
		out.Sequences[out.Count] = uint64(row[0].(int64))
		out.Count++
		out.EncodedBytes += uint32(len(blob)) + 10
		out.NextSequence = uint64(row[0].(int64))
		clear(row[:])
	}
}

// EncodeAuditPage produces only the bounded controlled-export representation.
// A transport must honor the independent management authorization before using
// this codec. Calling it grants no audit-read or export permission.
func EncodeAuditPage(dst []byte, page AuditPage) (int, error) {
	if page.Count > AuditPageRecords || page.EncodedBytes > AuditPageBytes || page.EncodedBytes < 32 || len(dst) < int(page.EncodedBytes) {
		return 0, ErrConfiguration
	}
	binary.BigEndian.PutUint64(dst[:8], uint64(page.Count))
	binary.BigEndian.PutUint64(dst[8:16], page.NextSequence)
	binary.BigEndian.PutUint64(dst[16:24], page.ThroughSequence)
	complete := uint64(0)
	if page.Complete {
		complete = 1
	}
	binary.BigEndian.PutUint64(dst[24:32], complete)
	offset := 32
	var scratch [auditRecordBytes]byte
	defer clear(scratch[:])
	for i, record := range page.Records[:page.Count] {
		n, err := EncodeAuditRecord(scratch[:], record)
		if err != nil || offset+10+n > int(page.EncodedBytes) {
			return 0, ErrConfiguration
		}
		binary.BigEndian.PutUint16(dst[offset:offset+2], uint16(n))
		binary.BigEndian.PutUint64(dst[offset+2:offset+10], page.Sequences[i])
		copy(dst[offset+10:offset+10+n], scratch[:n])
		offset += 10 + n
	}
	if offset != int(page.EncodedBytes) {
		return 0, ErrConfiguration
	}
	return offset, nil
}

type AuditExportReceipt struct {
	Sequence uint64
	EventID  [16]byte
}

// AcknowledgeAuditExport changes only delivery metadata of exact original IDs.
// It is idempotent; acknowledgement never deletes retained audit facts. The
// authenticated exporter owns the assertion that external persistence succeeded.
func (j *SQLiteTopUpServer) AcknowledgeAuditExport(ctx context.Context, access AuditAccess, receipts []AuditExportReceipt) error {
	a, principal, err := j.beginAudit(ctx, access, AuditOutboxExport)
	if err != nil {
		return err
	}
	defer j.store.end()
	if len(receipts) == 0 || len(receipts) > AuditPageRecords {
		return ErrAuditUnavailable
	}
	// Freeze the caller's bounded input before entering the durable operation.
	var frozen [AuditPageRecords]AuditExportReceipt
	copy(frozen[:], receipts)
	guard := func() error { return a.guard(ctx, access, AuditOutboxExport, principal) }
	err = j.store.writeTransaction(ctx, guard, func() error {
		m, err := a.meta()
		if err != nil {
			return err
		}
		for index, receipt := range frozen[:len(receipts)] {
			if receipt.Sequence == 0 || receipt.Sequence > math.MaxInt64 || receipt.EventID == ([16]byte{}) {
				return ErrAuditUnavailable
			}
			// A single request is one durable acknowledgement transaction. Do
			// not let duplicate sequence/ID pairs make the pending counters
			// depend on caller ordering or silently acknowledge two different
			// events under one sequence.
			for _, prior := range frozen[:index] {
				if prior.Sequence == receipt.Sequence || prior.EventID == receipt.EventID {
					return ErrAuditUnavailable
				}
			}
			var safety, delivered bool
			err := a.store.readOne("SELECT "+auditRowColumns+" FROM audit_events WHERE revision=?1", 7, func(row []driver.Value) error {
				record, _, exported, err := a.recordRow(row)
				if err != nil || record.EventID != receipt.EventID {
					return ErrAuditUnavailable
				}
				safety, delivered = record.Action == AuditSourceRevoked, exported
				return nil
			}, named(1, int64(receipt.Sequence)))
			if err != nil {
				return err
			}
			if delivered {
				continue
			}
			if err = a.store.exec("UPDATE audit_events SET exported=1 WHERE revision=?1 AND event_id=?2 AND exported=0", named(1, int64(receipt.Sequence)), named(2, receipt.EventID[:])); err != nil {
				return err
			}
			if err = a.store.changedOne(); err != nil {
				return err
			}
			if safety {
				if m.safetyPending == 0 {
					return ErrStorageFormat
				}
				m.safetyPending--
			} else {
				if m.ordinaryPending == 0 {
					return ErrStorageFormat
				}
				m.ordinaryPending--
			}
		}
		if err = a.store.exec("UPDATE audit_meta SET ordinary_pending=?1,safety_pending=?2 WHERE id=1", named(1, int64(m.ordinaryPending)), named(2, int64(m.safetyPending))); err != nil {
			return err
		}
		return a.store.changedOne()
	})
	return auditFailure(err)
}

// ExpireAudit is fixed retention maintenance, never an arbitrary delete API.
// The trusted lower bound must pass each event's original upper+retention
// deadline. Physical deletion uses secure_delete and a completed WAL truncation;
// a failed checkpoint is not reported as successful cleanup. Host snapshots and
// external exporter copies have independent retention/protection obligations.
func (j *SQLiteTopUpServer) ExpireAudit(ctx context.Context, access AuditAccess) error {
	a, principal, err := j.beginAudit(ctx, access, AuditRetentionMaintenance)
	if err != nil {
		return err
	}
	defer j.store.end()
	guard := func() error { return a.guard(ctx, access, AuditRetentionMaintenance, principal) }
	var lost uint64
	err = j.store.writeTransaction(ctx, guard, func() error {
		now, err := a.clock.Sample()
		if err != nil {
			return err
		}
		mode, err := a.store.scalar("PRAGMA secure_delete")
		if err != nil || mode != int64(1) {
			return ErrStorageUnavailable
		}
		m, err := a.meta()
		if err != nil {
			return err
		}
		var expired [4]uint32
		err = a.store.readOne("SELECT coalesce(sum(safety=0),0),coalesce(sum(safety=1),0),coalesce(sum(safety=0 AND exported=0),0),coalesce(sum(safety=1 AND exported=0),0) FROM audit_events WHERE expires<=?1", 4, func(row []driver.Value) error {
			for i := range expired {
				n, ok := row[i].(int64)
				if !ok || n < 0 || n > int64(a.policy.OrdinaryRecords+a.policy.SafetyRecords) {
					return ErrStorageFormat
				}
				expired[i] = uint32(n)
			}
			return nil
		}, named(1, sqliteUint(now.LowerMS)))
		if err != nil {
			return err
		}
		if expired[0] > m.ordinary || expired[1] > m.safety || expired[2] > m.ordinaryPending || expired[3] > m.safetyPending {
			return ErrStorageFormat
		}
		if err = a.store.exec("DELETE FROM audit_events WHERE expires<=?1", named(1, sqliteUint(now.LowerMS))); err != nil {
			return err
		}
		lost = uint64(expired[2]) + uint64(expired[3])
		if err = a.store.exec("UPDATE audit_meta SET ordinary_count=?1,safety_count=?2,ordinary_pending=?3,safety_pending=?4 WHERE id=1", named(1, int64(m.ordinary-expired[0])), named(2, int64(m.safety-expired[1])), named(3, int64(m.ordinaryPending-expired[2])), named(4, int64(m.safetyPending-expired[3]))); err != nil {
			return err
		}
		return a.store.changedOne()
	})
	if err != nil {
		return auditFailure(err)
	}
	auditIncrement(&a.expiredUnexported, lost)
	return auditFailure(j.store.checkpoint())
}
