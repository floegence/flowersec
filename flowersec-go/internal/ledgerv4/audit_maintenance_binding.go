package ledgerv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// AuditMaintenanceBinding belongs to one original scheduler through all actual
// worker exits. Releasing it is a trusted composition action, not cancellation.
// A closed but physically running scheduler cannot admit its own replacement.
type AuditMaintenanceBinding struct {
	mu                    sync.Mutex
	archive               *SQLiteAuditArchive
	source                *SQLiteTopUpServer
	archivePin, sourcePin resourcev4.Reference
}

func AuditMaintenanceBindingBytes() uint64 { return uint64(unsafe.Sizeof(AuditMaintenanceBinding{})) }
func (b *AuditMaintenanceBinding) Release() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.archive == nil {
		return
	}
	a, j := b.archive, b.source
	a.store.mu.Lock()
	j.store.mu.Lock()
	if a.maintenance == b {
		a.maintenance = nil
	}
	if j.maintenance == b {
		j.maintenance = nil
	}
	j.store.mu.Unlock()
	a.store.mu.Unlock()
	b.archivePin.Release()
	b.sourcePin.Release()
	b.archivePin, b.sourcePin = resourcev4.Reference{}, resourcev4.Reference{}
	b.archive, b.source = nil, nil
}

// BindMaintenance retains both original stores for one separately admitted
// local service. Its schedule uses their exact shared clock, source and
// retention; duplicate private roots cannot provide another budget. Export and
// retention permissions are checked here and again by every actual operation.
func (a *SQLiteAuditArchive) BindMaintenance(ref resourcev4.Reference, clock *timev4.Clock, source *SQLiteTopUpServer, archiveAccess, sourceAccess AuditAccess) (binding *AuditMaintenanceBinding, retention uint64, err error) {
	if a == nil || a.store == nil || source == nil || source.store == nil || clock == nil || a.store.sqliteStore == source.store.sqliteStore {
		return nil, 0, ErrConfiguration
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	source.store.mu.Lock()
	defer source.store.mu.Unlock()
	if a.store.closed || a.store.retired || source.store.closed || source.store.retired || source.audit == nil || a.config.Clock != clock || source.config.Clock != clock {
		return nil, 0, ErrConfiguration
	}
	if a.maintenance != nil || source.maintenance != nil {
		return nil, 0, ErrCapacity
	}
	c := a.config
	s := source.store
	if s.identity != c.Source || source.config.Tenant != c.Tenant || source.config.Source != c.Object || source.audit.policy.RetentionMS != c.RetentionMS {
		return nil, 0, ErrConfiguration
	}
	for _, owner := range []resourcev4.Reference{a.store.reservation, s.reservation} {
		if err := owner.CheckSameEnvironment(ref); err != nil {
			return nil, 0, err
		}
	}
	p, err := a.authorize(archiveAccess, AuditOutboxExport)
	if err != nil {
		return nil, 0, err
	}
	other, err := a.authorize(archiveAccess, AuditRetentionMaintenance)
	if err != nil {
		return nil, 0, err
	}
	if p != other {
		return nil, 0, ErrAuditDenied
	}
	p, err = source.audit.authorize(sourceAccess, AuditOutboxExport)
	if err != nil {
		return nil, 0, err
	}
	other, err = source.audit.authorize(sourceAccess, AuditRetentionMaintenance)
	if err != nil {
		return nil, 0, err
	}
	if p != other {
		return nil, 0, ErrAuditDenied
	}
	archivePin, err := a.store.reservation.Borrow()
	if err != nil {
		return nil, 0, err
	}
	sourcePin, err := s.reservation.Borrow()
	if err != nil {
		archivePin.Release()
		return nil, 0, err
	}
	binding = &AuditMaintenanceBinding{archive: a, source: source, archivePin: archivePin, sourcePin: sourcePin}
	a.maintenance, source.maintenance = binding, binding
	return binding, c.RetentionMS, nil
}
