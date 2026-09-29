package ledgerv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
	"testing"
)

// OperationsStoreHarness exposes actual SQL boundaries to external composition
// tests. The independent authority and management principal remain fixtures.
type OperationsStoreHarness struct {
	f      *topUpServerFixture
	access *auditAccessFixture
	Store  *SQLiteTopUpServer
	Root   *resourcev4.Root
	Clock  *timev4.Clock
	Access AuditAccess
}

func NewOperationsStoreHarness(t *testing.T) *OperationsStoreHarness {
	f := newTopUpServerFixture(t)
	access := newAuditAccess(f, AuditOperationsRead)
	return &OperationsStoreHarness{f: f, access: access, Store: f.server, Root: f.root, Clock: f.clock, Access: access}
}
func (h *OperationsStoreHarness) Reserve(cost resourcev4.Vector) resourcev4.Reference {
	return h.f.reserve(cost, 1)
}
func (h *OperationsStoreHarness) Revoke() { h.access.revoked.Store(true) }
func (h *OperationsStoreHarness) AfterQuery(callback func()) {
	h.Store.store.querier = &auditQueryFault{QueryerContext: h.Store.store.querier, after: func(string) { callback() }}
}
