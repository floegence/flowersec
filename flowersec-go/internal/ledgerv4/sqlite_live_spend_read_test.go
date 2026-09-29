package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type liveReadAccess struct {
	target         LiveSpendReadTarget
	denied         atomic.Bool
	materialChecks atomic.Int32
}

func (a *liveReadAccess) Target(SQLiteIdentity) (LiveSpendReadTarget, error) {
	if a.denied.Load() {
		return LiveSpendReadTarget{}, ErrDenied
	}
	return a.target, nil
}
func (a *liveReadAccess) CheckMaterial(_ SQLiteIdentity, target LiveSpendReadTarget, _ *protocolv4.SignedMap) error {
	a.materialChecks.Add(1)
	if a.denied.Load() || target != a.target {
		return ErrDenied
	}
	return nil
}

type liveReadFixture struct {
	*sqliteFixture
	store                *SQLiteStore
	time                 *Invocation
	advance              atomic.Uint64
	access               *liveReadAccess
	key, spending, proof []byte
}

func newLiveReadFixture(t *testing.T, consumed bool, outcome uint64) *liveReadFixture {
	t.Helper()
	f := &liveReadFixture{sqliteFixture: newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 128, MaxRecords: 16, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})}
	f.store = f.create()
	f.time = invocation(t, &f.advance)
	f.access = &liveReadAccess{target: LiveSpendReadTarget{Tenant: "tenant", Audience: "service", Issuer: [16]byte{1}, Lease: [16]byte{2}, Attempt: [16]byte{3}, ClientIdentity: [32]byte{4}, RequestDigest: [32]byte{5}}}
	target := f.access.target
	var server, artifact, route [32]byte
	server[0], artifact[0], route[0] = 6, 7, 8
	candidate := [16]byte{9}
	fields := []protocolv4.Field{
		{Name: "schema_revision", Number: 1}, {Name: "authority_id", Kind: protocolv4.TextString, Text: f.identity.Authority}, {Name: "signing_key_id", Kind: protocolv4.TextString, Text: "activation"}, {Name: "tenant_id", Kind: protocolv4.TextString, Text: target.Tenant},
		{Name: "artifact_issuer_key_id", Kind: protocolv4.ByteString, Bytes: target.Issuer[:]}, {Name: "lease_id", Kind: protocolv4.ByteString, Bytes: target.Lease[:]}, {Name: "artifact_digest", Kind: protocolv4.ByteString, Bytes: artifact[:]}, {Name: "candidate_selection", Kind: protocolv4.ByteString, Bytes: candidate[:]}, {Name: "route_selection", Kind: protocolv4.ByteString, Bytes: route[:]}, {Name: "attempt_id", Kind: protocolv4.ByteString, Bytes: target.Attempt[:]}, {Name: "client_identity_digest", Kind: protocolv4.ByteString, Bytes: target.ClientIdentity[:]}, {Name: "server_identity_digest", Kind: protocolv4.ByteString, Bytes: server[:]}, {Name: "audience", Kind: protocolv4.TextString, Text: target.Audience}, {Name: "issued_at_ms", Number: 100000}, {Name: "activation_not_after_ms", Number: 108000}, {Name: "session_not_after_ms", Number: 120000},
	}
	limit, err := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewSignedMapCodec("ActivationAuthorization", limit, limit)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Sign(fields, [32]byte{1}, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := signed.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	f.proof = bytes.Clone(wire)
	signer := signed.Key()
	signed.Release()
	// The fixture's last field is the registered signature (16, bstr(64));
	// preserve the preceding canonical bytes as the original unsigned TxA map.
	unsigned := bytes.Clone(f.proof[:len(f.proof)-67])
	if unsigned[0] != 0xb1 {
		t.Fatal("unexpected fixture map")
	}
	unsigned[0] = 0xb0
	record := admissionRecord{fields: protocolv4.AdmissionFields{Tenant: target.Tenant, Issuer: target.Issuer, Lease: target.Lease}}
	f.key = make([]byte, admissionKeyBytes)
	n, err := record.key(f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.key = f.key[:n]
	w := admissionWriter{dst: make([]byte, 65536)}
	w.text("flowersec/live-spending/2")
	for _, value := range []uint64{1, f.store.epoch, f.identity.Generation, 1, 101000, 108000, 100000, 0} {
		w.uint(value)
	}
	w.uint(109000)
	w.uint(120000)
	for _, value := range []string{f.identity.Authority, target.Tenant, target.Audience} {
		w.text(value)
	}
	invocation, intent := [16]byte{10}, [32]byte{11}
	for _, value := range [][]byte{f.identity.StoreID[:], invocation[:], target.RequestDigest[:], intent[:], candidate[:], route[:], artifact[:], signer[:], target.Issuer[:], target.Lease[:], target.Attempt[:], target.ClientIdentity[:], server[:]} {
		w.bytes(value)
	}
	w.uint(uint64(len(unsigned)))
	w.bytes(unsigned)
	if w.err != nil {
		t.Fatal(w.err)
	}
	f.spending = bytes.Clone(w.dst[:w.n])
	projection, state, version := f.spending, int64(0), uint64(1)
	if consumed {
		proof := f.proof
		if outcome != 2 {
			proof = nil
		}
		projection = make([]byte, 65536)
		n, err = encodeLiveConsumed(projection, f.spending, proof, f.store.epoch, outcome, 100000)
		if err != nil {
			t.Fatal(err)
		}
		projection, state, version = projection[:n], 1, 2
	}
	err = f.store.writeTransaction(context.Background(), func() error { return nil }, func() error {
		if err := f.store.exec("INSERT INTO spend VALUES (?1,0,?2,?3,?4,?5)", named(1, f.key), named(2, state), named(3, sqliteUint(version)), named(4, sqliteUint(f.store.epoch)), named(5, projection)); err != nil {
			return err
		}
		return f.store.exec("UPDATE manifest SET spend_rows=spend_rows+1 WHERE id=1")
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *liveReadFixture) reader(t *testing.T) *SQLiteLiveSpendRead {
	t.Helper()
	charge, err := SQLiteLiveSpendReadCharge(f.backing.limits.MaxRecordBytes, 4096)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSQLiteLiveSpendRead(context.Background(), f.store, f.access, f.time.clock, f.time.deadline, 4096, f.reserve(charge, 1), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestSQLiteLiveMaterialReadAfterRestartPreservesExactBytesAndCommit(t *testing.T) {
	f := newLiveReadFixture(t, true, 2)
	closeSQLite(t, f.store)
	var err error
	f.store, err = f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	f.advance.Store(1500) // The old invocation is expired; only its material cap applies.
	original, err := f.store.scalar("SELECT projection FROM spend")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		r := f.reader(t)
		err = r.DeliverClientMaterial(func(_ context.Context, proof []byte) error {
			if !bytes.Equal(proof, f.proof) {
				t.Fatal("read regenerated original bytes")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := f.store.scalar("SELECT projection FROM spend")
	if err != nil || !bytes.Equal(original.([]byte), after.([]byte)) {
		t.Fatal("material read rewrote TxB", err)
	}
	fence, err := f.store.scalar("SELECT fence FROM spend")
	if err != nil || !bytes.Equal(fence.([]byte), sqliteUint(1)) {
		t.Fatal("material read replaced original commit fence", err)
	}
	if f.access.materialChecks.Load() != 2 {
		t.Fatal("read skipped current trust checks")
	}
}

func TestSQLiteLiveRecoveryOnlyEndsExpiredIntent(t *testing.T) {
	f := newLiveReadFixture(t, false, 0)
	r := f.reader(t)
	receipt, err := r.RecoverExpired()
	if err != nil || receipt.State != SpendSpending {
		t.Fatal(receipt, err)
	}
	if err = r.Cleanup(); err != nil {
		t.Fatal(err)
	}
	closeSQLite(t, f.store)
	f.store, err = f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	f.advance.Store(1000)
	r = f.reader(t)
	receipt, err = r.RecoverExpired()
	if err != nil || receipt.State != SpendConsumed || receipt.AuthorizationOutcome != AuthorizationUnknown || receipt.UpdatedAtMS != 101000 {
		t.Fatal(receipt, err)
	}
	if err = r.Cleanup(); err != nil {
		t.Fatal(err)
	}
	r = f.reader(t)
	err = r.DeliverClientMaterial(func(context.Context, []byte) error { t.Fatal("recovery manufactured material"); return nil })
	if !errors.Is(err, ErrMaterialNotReady) {
		t.Fatal(err)
	}
	v, err := f.store.readLiveSpend(f.key, make([]byte, 65536))
	if err != nil || v.fence != 2 || v.originalFence != 1 || !bytes.Equal(v.spending, f.spending) {
		t.Fatal("recovery changed original intent", v, err)
	}
}

func TestSQLiteLiveReadRefusesMismatchedExpiredAndRevokedRequests(t *testing.T) {
	for _, mode := range []string{"binding", "expiry", "revoked", "projection", "missing_proof", "one_task"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveReadFixture(t, true, 2)
			switch mode {
			case "binding":
				f.access.target.RequestDigest[0]++
			case "expiry":
				f.advance.Store(8000)
			case "projection":
				changed := bytes.Clone(f.spending)
				changed[len(changed)-1] ^= 1
				target := make([]byte, 65536)
				n, err := encodeLiveConsumed(target, changed, f.proof, 1, 2, 100000)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.exec("UPDATE spend SET projection=?1", named(1, target[:n])); err != nil {
					t.Fatal(err)
				}
			case "missing_proof":
				target := make([]byte, 65536)
				n, err := encodeLiveConsumed(target, f.spending, nil, 1, 2, 100000)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.exec("UPDATE spend SET projection=?1", named(1, target[:n])); err != nil {
					t.Fatal(err)
				}
			}
			r := f.reader(t)
			if mode == "revoked" {
				f.access.denied.Store(true)
			}
			if mode == "one_task" {
				if _, err := r.Receipt(); err != nil {
					t.Fatal(err)
				}
			}
			err := r.DeliverClientMaterial(func(context.Context, []byte) error { t.Fatal("ineligible material delivered"); return nil })
			if err == nil {
				t.Fatal("ineligible material accepted")
			}
		})
	}
}

func TestSQLiteLiveReadCloseRetainsActualResponseTail(t *testing.T) {
	f := newLiveReadFixture(t, true, 2)
	r := f.reader(t)
	entered, release, done := make(chan context.Context, 1), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- r.DeliverClientMaterial(func(ctx context.Context, _ []byte) error { entered <- ctx; <-release; return ctx.Err() })
	}()
	ctx := <-entered
	before := f.root.Snapshot().Charged
	r.Close()
	if err := r.Cleanup(); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if f.root.Snapshot().Charged != before || len(r.row) == 0 {
		t.Fatal("response tail refunded")
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("close did not cancel response writer")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := r.Cleanup(); err != nil {
		t.Fatal(err)
	}
}
