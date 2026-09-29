package ledgerv4

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// AuditTransferResult distinguishes confirmed destination persistence from the
// original source acknowledgement. Unknown calls never advance the page cursor;
// retry starts from the original query and deduplicates exact existing event IDs.
// This is a controlled export result, not a public diagnostic or protocol fact.
type AuditTransferResult struct {
	Persistence, Acknowledgement  string
	Count                         uint16
	NextSequence, ThroughSequence uint64
	Complete                      bool
}

// exportArchiveBinding performs no SQL and checks only the actual configured
// source, retention and independent export permission. Borrowing is bounded by
// that source's original root references and survives logical Close/Retire.
func (j *SQLiteTopUpServer) exportArchiveBinding(c SQLiteAuditArchiveConfig, access AuditAccess, borrow bool) (AuditPrincipal, resourcev4.Reference, error) {
	if j == nil || j.store == nil {
		return AuditPrincipal{}, resourcev4.Reference{}, ErrAuditUnavailable
	}
	s := j.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired || j.audit == nil {
		return AuditPrincipal{}, resourcev4.Reference{}, ErrAuditUnavailable
	}
	if s.identity != c.Source || j.config.Tenant != c.Tenant || j.config.Source != c.Object || j.audit.policy.RetentionMS != c.RetentionMS {
		return AuditPrincipal{}, resourcev4.Reference{}, ErrAuditDenied
	}
	if err := s.reservation.Check(); err != nil {
		return AuditPrincipal{}, resourcev4.Reference{}, ErrAuditUnavailable
	}
	principal, err := j.audit.authorize(access, AuditOutboxExport)
	if err != nil {
		return AuditPrincipal{}, resourcev4.Reference{}, err
	}
	var pin resourcev4.Reference
	if borrow {
		pin, err = s.reservation.Borrow()
	}
	return principal, pin, err
}

// TransferAuditPage uses the existing original outbox. It never accepts caller
// supplied records, fabricates a successful ACK after unknown persistence, or
// removes source history. There is one synchronous transfer with no retry task.
// Source and destination independently authorize the exporter. Both storage
// operations remain charged through their actual return, including Close tails.
func (a *SQLiteAuditArchive) TransferAuditPage(ctx context.Context, archiveAccess AuditAccess, source *SQLiteTopUpServer, sourceAccess AuditAccess, query AuditQuery) (AuditTransferResult, error) {
	result := AuditTransferResult{Persistence: "not_started", Acknowledgement: "not_started", NextSequence: query.AfterSequence, ThroughSequence: query.ThroughSequence}
	principal, err := a.begin(ctx, archiveAccess, AuditOutboxExport)
	if err != nil {
		return result, err
	}
	defer a.store.end()
	sourcePrincipal, pin, err := source.exportArchiveBinding(a.config, sourceAccess, true)
	if err != nil {
		return result, auditFailure(err)
	}
	defer pin.Release()
	sourceGuard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, _, err := source.exportArchiveBinding(a.config, sourceAccess, false)
		if err != nil || current != sourcePrincipal {
			return ErrAuditDenied
		}
		return nil
	}
	if err := a.guard(ctx, archiveAccess, AuditOutboxExport, principal); err != nil {
		return result, auditFailure(err)
	}
	page, err := source.ExportAudit(ctx, sourceAccess, query)
	if err != nil {
		return result, err
	}
	// Clear this original local copy before releasing its admitted archive owner.
	defer clear(page.Records[:])
	result.Count = page.Count
	result.ThroughSequence = page.ThroughSequence
	if err := sourceGuard(); err != nil {
		return result, auditFailure(err)
	}
	if page.Count == 0 {
		if err := a.guard(ctx, archiveAccess, AuditOutboxExport, principal); err != nil {
			return result, auditFailure(err)
		}
		result.NextSequence, result.Complete = page.NextSequence, page.Complete
		return result, nil
	}
	result.Persistence = "unknown"
	receipts, count, err := a.persistPage(ctx, archiveAccess, principal, a.config.Source, page, sourceGuard)
	if err != nil {
		return result, err
	}
	result.Persistence = "committed"
	if err := sourceGuard(); err != nil {
		return result, auditFailure(err)
	}
	if err := a.guard(ctx, archiveAccess, AuditOutboxExport, principal); err != nil {
		return result, auditFailure(err)
	}
	result.Acknowledgement = "unknown"
	if err := source.AcknowledgeAuditExport(ctx, sourceAccess, receipts[:count]); err != nil {
		return result, err
	}
	result.Acknowledgement = "committed"
	result.NextSequence, result.Complete = page.NextSequence, page.Complete
	return result, nil
}
