package ledgerv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// BorrowOperations retains this original store's aggregate owner, but grants
// no read authority. Each management query still needs independent AuditAccess.
func (j *SQLiteTopUpServer) BorrowOperations(ref resourcev4.Reference) (resourcev4.Reference, error) {
	if j == nil || j.store == nil {
		return resourcev4.Reference{}, ErrOwner
	}
	s := j.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if err := s.reservation.CheckSameEnvironment(ref); err != nil {
		return resourcev4.Reference{}, err
	}
	return s.reservation.Borrow()
}

// OperationsAuthorization is a bounded local output guard. It makes no SQL
// query and cannot confer sensitive-record, audit-read, export or write access.
func (j *SQLiteTopUpServer) OperationsAuthorization(access AuditAccess) (AuditPrincipal, error) {
	if j == nil || j.store == nil {
		return AuditPrincipal{}, ErrAuditUnavailable
	}
	s := j.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired || j.audit == nil {
		return AuditPrincipal{}, ErrAuditUnavailable
	}
	if err := s.reservation.Check(); err != nil {
		return AuditPrincipal{}, ErrAuditUnavailable
	}
	return j.audit.authorize(access, AuditOperationsRead)
}
