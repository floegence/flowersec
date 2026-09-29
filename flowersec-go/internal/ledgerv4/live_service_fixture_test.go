package ledgerv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveServiceTestHarness exposes the actual signed SQLite row to external
// control-service tests without giving production code a row insertion API.
type LiveServiceTestHarness struct {
	f        *liveReadFixture
	Store    *SQLiteStore
	Access   LiveSpendReadAccess
	Clock    *timev4.Clock
	Deadline *timev4.Deadline
}

func NewLiveServiceTestHarness(t *testing.T, consumed bool, outcome uint64) *LiveServiceTestHarness {
	f := newLiveReadFixture(t, consumed, outcome)
	return &LiveServiceTestHarness{f: f, Store: f.store, Access: f.access, Clock: f.time.clock, Deadline: f.time.deadline}
}
func (h *LiveServiceTestHarness) Reserve(c resourcev4.Vector) resourcev4.Reference {
	return h.f.reserve(c, 1)
}
func (h *LiveServiceTestHarness) Tick(n uint64) { h.f.advance.Store(n) }
func (h *LiveServiceTestHarness) Deny(b bool)   { h.f.access.denied.Store(b) }
func (h *LiveServiceTestHarness) Proof() []byte { return h.f.proof }
func (h *LiveServiceTestHarness) Snapshot() resourcev4.Snapshot {
	return h.f.root.Snapshot()
}
