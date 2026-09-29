package ledgerv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// This test-only fixture exposes real SQLite transactions to external control
// adapter tests without a production import cycle. Its issuer authority and
// certificate are ledger fixtures, not credential/provider qualification.
type PoolServiceTestHarness struct {
	f              *topUpServerFixture
	Store          *SQLiteTopUpServer
	Access         TopUpAccess
	Client         *SQLiteTopUpJournal
	ClientIdentity SQLiteIdentity
}

func NewPoolServiceTestHarness(t *testing.T) *PoolServiceTestHarness {
	return NewPoolServiceAuditTestHarness(t, SQLiteAuditPolicy{})
}
func NewPoolServiceAuditTestHarness(t *testing.T, policy SQLiteAuditPolicy) *PoolServiceTestHarness {
	f := newTopUpServerFixtureWithAudit(t, policy)
	client, journal, _ := newTerminalClient(t, f)
	return &PoolServiceTestHarness{f: f, Store: f.server, Access: f.authority, Client: journal, ClientIdentity: client.identity}
}
func (h *PoolServiceTestHarness) Reserve(cost resourcev4.Vector) resourcev4.Reference {
	return h.f.reserve(cost, 1)
}
func (h *PoolServiceTestHarness) Request(t *testing.T, sequence uint64) (protocolv4.TopUpRequestFacts, []byte) {
	t.Helper()
	r, _ := h.f.request(sequence, 1)
	var e error
	r.Identity, e = protocolv4.TopUpIdentityDigest([]byte{0xa0})
	if e != nil {
		t.Fatal(e)
	}
	return serverTopUpRequest(t, r, 9000)
}
func (h *PoolServiceTestHarness) Begin(t *testing.T, r protocolv4.TopUpRequestFacts) {
	t.Helper()
	if e := h.Client.Begin(context.Background(), r, []byte{0xa0}, []byte("original-key")); e != nil {
		t.Fatal(e)
	}
}
func (h *PoolServiceTestHarness) Response(t *testing.T, r protocolv4.TopUpRequestFacts) ([]byte, protocolv4.TopUpResponseFacts) {
	return serverTopUpResponse(t, r, 1, false, 0)
}
func (h *PoolServiceTestHarness) Ack(t *testing.T, r protocolv4.TopUpRequestFacts, f protocolv4.TopUpResponseFacts) []byte {
	return serverTopUpAck(t, r, f, 1)
}
func (h *PoolServiceTestHarness) Tick(n uint64) { h.f.tick.Store(n) }
func (h *PoolServiceTestHarness) Denied(b bool) { h.f.authority.denied.Store(b) }
func (h *PoolServiceTestHarness) Fence() {
	h.f.authority.commitGate.Lock()
	h.f.authority.permanent.Store(true)
	h.f.authority.commitGate.Unlock()
}
func (h *PoolServiceTestHarness) LoseCommitConfirmation() func() {
	original := h.Store.store.execer
	fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost commit confirmation") }}
	fault.commits.Store(1)
	h.Store.store.execer = fault
	return func() { h.Store.store.execer = original }
}
