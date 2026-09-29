package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"math"
)

// persistPage runs inside the archive's one original admitted transfer. Only
// the authenticated source reader supplies production pages to this method.
func (a *SQLiteAuditArchive) persistPage(ctx context.Context, access AuditAccess, principal AuditPrincipal, source SQLiteIdentity, page AuditPage, sourceGuard func() error) ([AuditPageRecords]AuditExportReceipt, uint16, error) {
	var receipts [AuditPageRecords]AuditExportReceipt
	if source != a.config.Source || page.Count == 0 || page.Count > AuditPageRecords {
		return receipts, 0, ErrAuditUnavailable
	}
	defer func() {
		for i := range a.scratch {
			clear(a.scratch[i][:])
		}
		clear(a.lengths[:])
	}()
	now, err := a.config.Clock.Sample()
	if err != nil {
		return receipts, 0, ErrAuditUnavailable
	}
	size := 32
	for i, record := range page.Records[:page.Count] {
		sequence := page.Sequences[i]
		if sequence == 0 || sequence > math.MaxInt64 || i > 0 && sequence <= page.Sequences[i-1] || !a.recordCurrent(record, now) {
			return receipts, 0, ErrAuditUnavailable
		}
		// Retain only the configured immutable tenant string during driver work.
		page.Records[i].Tenant = a.config.Tenant
		a.lengths[i], err = EncodeAuditRecord(a.scratch[i][:], page.Records[i])
		if err != nil {
			return receipts, 0, ErrAuditUnavailable
		}
		size += a.lengths[i] + 10
	}
	if size > AuditPageBytes {
		return receipts, 0, ErrAuditCapacity
	}
	guard := func() error {
		if sourceGuard != nil {
			if err := sourceGuard(); err != nil {
				return err
			}
		}
		if err := a.guard(ctx, access, AuditOutboxExport, principal); err != nil {
			return err
		}
		now, err := a.config.Clock.Sample()
		if err != nil {
			return ErrAuditUnavailable
		}
		for _, record := range page.Records[:page.Count] {
			if !a.recordCurrent(record, now) {
				return ErrAuditUnavailable
			}
		}
		return nil
	}
	err = a.store.writeTransaction(ctx, guard, func() error {
		count, err := a.count()
		if err != nil {
			return err
		}
		for i, record := range page.Records[:page.Count] {
			sequence := page.Sequences[i]
			existing, err := a.store.scalar("SELECT count(*) FROM archived_events WHERE event_id=?1 OR sequence=?2", named(1, record.EventID[:]), named(2, int64(sequence)))
			if err != nil {
				return err
			}
			switch existing {
			case int64(0):
				if count == a.config.Records {
					return ErrAuditCapacity
				}
				if err := a.store.exec("INSERT INTO archived_events VALUES(?1,?2,?3,?4,?5)", named(1, record.EventID[:]), named(2, int64(sequence)), named(3, sqliteUint(record.UTCMS)), named(4, sqliteUint(record.UTCMS+a.config.RetentionMS)), named(5, a.scratch[i][:a.lengths[i]])); err != nil {
					return err
				}
				count++
			case int64(1):
				if err := a.store.readOne("SELECT "+auditArchiveColumns+" FROM archived_events WHERE event_id=?1 OR sequence=?2", 5, func(row []driver.Value) error {
					prior, err := a.recordRow(row)
					if err != nil || prior != record || row[0] != int64(sequence) || !bytes.Equal(row[4].([]byte), a.scratch[i][:a.lengths[i]]) {
						return ErrConflict
					}
					return nil
				}, named(1, record.EventID[:]), named(2, int64(sequence))); err != nil {
					return err
				}
			default:
				return ErrConflict
			}
		}
		if err := a.store.exec("UPDATE manifest SET records_count=?1 WHERE id=1", named(1, int64(count))); err != nil {
			return err
		}
		return a.store.changedOne()
	})
	if err == nil {
		err = guard()
	}
	if err != nil {
		return receipts, 0, auditFailure(err)
	}
	for i, record := range page.Records[:page.Count] {
		receipts[i] = AuditExportReceipt{Sequence: page.Sequences[i], EventID: record.EventID}
	}
	return receipts, page.Count, nil
}

// ExpireAuditArchive has no caller-selected cutoff. It deletes only the
// original expired records, then requires physical WAL truncation before success.
func (a *SQLiteAuditArchive) ExpireAuditArchive(ctx context.Context, access AuditAccess) error {
	principal, err := a.begin(ctx, access, AuditRetentionMaintenance)
	if err != nil {
		return err
	}
	defer a.store.end()
	guard := func() error { return a.guard(ctx, access, AuditRetentionMaintenance, principal) }
	err = a.store.writeTransaction(ctx, guard, func() error {
		mode, err := a.store.scalar("PRAGMA secure_delete")
		if err != nil || mode != int64(1) {
			return ErrStorageUnavailable
		}
		now, err := a.config.Clock.Sample()
		if err != nil {
			return ErrAuditUnavailable
		}
		before, err := a.count()
		if err != nil {
			return err
		}
		if err := a.store.exec("DELETE FROM archived_events WHERE expires<=?1", named(1, sqliteUint(now.LowerMS))); err != nil {
			return err
		}
		changed, err := a.store.scalar("SELECT changes()")
		if err != nil {
			return err
		}
		n, ok := changed.(int64)
		if !ok || n < 0 || uint64(n) > uint64(before) {
			return ErrStorageFormat
		}
		if err := a.store.exec("UPDATE manifest SET records_count=?1 WHERE id=1", named(1, int64(before)-n)); err != nil {
			return err
		}
		return a.store.changedOne()
	})
	if err != nil {
		return auditFailure(err)
	}
	return auditFailure(a.store.checkpoint())
}

type AuditArchiveStatus struct {
	Records, Capacity          uint32
	RetentionMS, ObservedUTCMS uint64
}

func (a *SQLiteAuditArchive) AuditArchiveStatus(ctx context.Context, access AuditAccess) (AuditArchiveStatus, error) {
	principal, err := a.begin(ctx, access, AuditOperationsRead)
	if err != nil {
		return AuditArchiveStatus{}, err
	}
	defer a.store.end()
	if err := a.guard(ctx, access, AuditOperationsRead, principal); err != nil {
		return AuditArchiveStatus{}, auditFailure(err)
	}
	count, err := a.count()
	if err != nil {
		return AuditArchiveStatus{}, auditFailure(err)
	}
	now, err := a.config.Clock.Sample()
	if err != nil {
		return AuditArchiveStatus{}, ErrAuditUnavailable
	}
	if err := a.guard(ctx, access, AuditOperationsRead, principal); err != nil {
		return AuditArchiveStatus{}, auditFailure(err)
	}
	return AuditArchiveStatus{Records: count, Capacity: a.config.Records, RetentionMS: a.config.RetentionMS, ObservedUTCMS: now.UpperMS}, nil
}
