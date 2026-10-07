package ledgerv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type namespaceRestoreFunc func(SQLiteIdentity, protocolv4.NamespaceContinuityScope, protocolv4.NamespaceContinuityVersion) error

func (f namespaceRestoreFunc) CheckNamespaceRestore(i SQLiteIdentity, s protocolv4.NamespaceContinuityScope, v protocolv4.NamespaceContinuityVersion) error {
	return f(i, s, v)
}

type sqliteNamespaceFixture struct {
	*sqliteFixture
	config SQLiteNamespaceConfig
	anchor protocolv4.NamespaceContinuityVersion
}

func newSQLiteNamespaceFixture(t *testing.T) *sqliteNamespaceFixture {
	t.Helper()
	f := &sqliteNamespaceFixture{sqliteFixture: newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 2048, MaxRecords: 64, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})}
	f.config.Scope = protocolv4.NamespaceContinuityScope{Tenant: "tenant", Authority: "revocation", Capacity: [32]byte{7}, Limits: protocolv4.NamespaceContinuityLimits{TrustConfigurations: 2, TrustConfigBytes: 32768, StateBytes: 2 << 20, FetchDurationMS: 90000, FetchAttempts: 3}}
	f.config.Restore = namespaceRestoreFunc(func(i SQLiteIdentity, s protocolv4.NamespaceContinuityScope, v protocolv4.NamespaceContinuityVersion) error {
		if i != f.identity || s != f.config.Scope || v != f.anchor {
			return ErrFenced
		}
		return nil
	})
	return f
}
func (f *sqliteNamespaceFixture) openHistory(create bool) (*SQLiteNamespaceHistory, error) {
	f.t.Helper()
	charge, err := SQLiteNamespaceHistoryCharge(f.backing.limits, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	r := f.reserve(charge, 1)
	defer r.Release()
	var h *SQLiteNamespaceHistory
	if create {
		h, err = CreateSQLiteNamespaceHistory(context.Background(), f.backing, f.identity, f.continuity, f.config, r, f.environment)
	} else {
		h, err = OpenSQLiteNamespaceHistory(context.Background(), f.backing, f.identity, f.continuity, f.config, r, f.environment)
	}
	if h != nil {
		f.stores = append(f.stores, h.store)
	}
	return h, err
}

// The storage adapter validates only bounded record structure. These opaque
// facts are deliberately not signatures; common recovery must reverify them.
func (f *sqliteNamespaceFixture) record(size int, marker byte) []byte {
	f.t.Helper()
	r := protocolv4.NamespaceContinuityRecord{TrustCount: 1, Active: protocolv4.NamespaceHeadHistory{TrustRevision: 1, Head: []byte{1}}, Observed: protocolv4.NamespaceHeadHistory{TrustRevision: 2, Head: []byte{2}}, State: bytes.Repeat([]byte{marker}, size), FetchDurationMS: 90000, FetchAttempts: 3, Pinned: protocolv4.NamespaceHeadHistory{TrustRevision: 2, Head: []byte{3}}, PinnedDeadlineMS: 8123456, PinnedAttempts: 2}
	r.Trust[0] = []byte{7}
	max, err := protocolv4.NamespaceContinuityRecordBytes(f.config.Scope.Limits)
	if err != nil {
		f.t.Fatal(err)
	}
	wire := make([]byte, int(max))
	n, err := protocolv4.EncodeNamespaceContinuityRecord(wire, f.config.Scope.Limits, r)
	if err != nil {
		f.t.Fatal(err)
	}
	return wire[:n]
}

func TestSQLiteNamespaceCompleteChunkedHistoryAndIndependentFreshness(t *testing.T) {
	f := newSQLiteNamespaceFixture(t)
	h, err := f.openHistory(true)
	if err != nil {
		t.Fatal(err)
	}
	first := f.record((1<<20)+123, 17)
	v, err := h.CommitNamespace(context.Background(), protocolv4.NamespaceContinuityVersion{}, first)
	if err != nil {
		t.Fatal(err)
	}
	f.anchor = v
	dst := make([]byte, 2<<20)
	got, n, err := h.LoadNamespace(context.Background(), dst)
	if err != nil || got != v || !bytes.Equal(dst[:n], first) {
		t.Fatal("complete chunked transaction lost history", err)
	}
	second := f.record(66500, 23)
	v2, err := h.CommitNamespace(context.Background(), v, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.LoadNamespace(context.Background(), dst); !errors.Is(err, ErrFenced) {
		t.Fatal("file attested its own freshness", err)
	}
	f.anchor = v2
	closeSQLite(t, h.store)
	h, err = f.openHistory(false)
	if err != nil {
		t.Fatal(err)
	}
	got, n, err = h.LoadNamespace(context.Background(), dst)
	if err != nil || got != v2 || !bytes.Equal(dst[:n], second) {
		t.Fatal("reopen lost complete replacement", err)
	}
	if _, err = h.CommitNamespace(context.Background(), v, first); !errors.Is(err, ErrConflict) {
		t.Fatal("old revision overwrote history", err)
	}
	count, err := h.store.scalar("SELECT count(*) FROM chunks")
	if err != nil || count != int64(2) {
		t.Fatal("old blob references survived atomic replacement", count, err)
	}
}

type namespaceChunkFault struct {
	driver.ExecerContext
	after bool
}

func (f *namespaceChunkFault) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !f.after && q == "UPDATE manifest SET snapshot_revision=?1,snapshot_digest=?2,snapshot_bytes=?3 WHERE id=1" {
		return nil, errors.New("fault before manifest publication")
	}
	if q == "COMMIT" && f.after {
		r, e := f.ExecerContext.ExecContext(ctx, q, args)
		if e != nil {
			return r, e
		}
		return r, errors.New("lost commit response")
	}
	return f.ExecerContext.ExecContext(ctx, q, args)
}

func TestSQLiteNamespaceChunkFailureCannotPublishPartialHistory(t *testing.T) {
	f := newSQLiteNamespaceFixture(t)
	h, err := f.openHistory(true)
	if err != nil {
		t.Fatal(err)
	}
	first := f.record(140000, 17)
	v, err := h.CommitNamespace(context.Background(), protocolv4.NamespaceContinuityVersion{}, first)
	if err != nil {
		t.Fatal(err)
	}
	f.anchor = v
	original := h.store.execer
	h.store.execer = &namespaceChunkFault{ExecerContext: original}
	if _, err = h.CommitNamespace(context.Background(), v, f.record(70000, 23)); err == nil {
		t.Fatal("fault accepted")
	}
	h.store.execer = original
	dst := make([]byte, len(first))
	got, n, err := h.LoadNamespace(context.Background(), dst)
	if err != nil || got != v || !bytes.Equal(dst[:n], first) {
		t.Fatal("rollback left a partial blob graph", err)
	}
}

func TestSQLiteNamespaceRejectsCorruptionAndIncompleteInitialization(t *testing.T) {
	for _, attack := range []string{"empty", "missing", "oversize", "digest"} {
		t.Run(attack, func(t *testing.T) {
			f := newSQLiteNamespaceFixture(t)
			h, err := f.openHistory(true)
			if err != nil {
				t.Fatal(err)
			}
			if attack != "empty" {
				f.anchor, err = h.CommitNamespace(context.Background(), protocolv4.NamespaceContinuityVersion{}, f.record(140000, 17))
				if err != nil {
					t.Fatal(err)
				}
			}
			switch attack {
			case "missing":
				err = h.store.exec("DELETE FROM chunks WHERE ordinal=1")
			case "oversize":
				err = h.store.exec("INSERT INTO chunks VALUES (99,?1)", named(1, []byte{1}))
			case "digest":
				err = h.store.exec("UPDATE chunks SET data=?1 WHERE ordinal=0", named(1, bytes.Repeat([]byte{3}, 65536)))
			}
			if err != nil {
				t.Fatal(err)
			}
			dst := bytes.Repeat([]byte{9}, 150000)
			if _, n, e := h.LoadNamespace(context.Background(), dst); e == nil || n != 0 {
				t.Fatal("invalid history delivered", n, e)
			}
			closeSQLite(t, h.store)
			if attack == "empty" || attack == "missing" || attack == "oversize" {
				if reopened, e := f.openHistory(false); e == nil || reopened != nil {
					t.Fatal("invalid schema history reopened", e)
				}
			}
		})
	}
}

func TestSQLiteNamespaceUnknownCommitRequiresIndependentRecovery(t *testing.T) {
	f := newSQLiteNamespaceFixture(t)
	h, err := f.openHistory(true)
	if err != nil {
		t.Fatal(err)
	}
	first := f.record(140000, 17)
	v, err := h.CommitNamespace(context.Background(), protocolv4.NamespaceContinuityVersion{}, first)
	if err != nil {
		t.Fatal(err)
	}
	f.anchor = v
	second := f.record(70000, 23)
	original := h.store.execer
	h.store.execer = &namespaceChunkFault{ExecerContext: original, after: true}
	result, err := h.CommitNamespace(context.Background(), v, second)
	if !errors.Is(err, ErrUnknown) || result != (protocolv4.NamespaceContinuityVersion{}) {
		t.Fatal("ambiguous commit minted receipt", result, err)
	}
	h.store.execer = original
	if _, _, err = h.LoadNamespace(context.Background(), make([]byte, len(first))); !errors.Is(err, ErrFenced) {
		t.Fatal("old anchor accepted changed history", err)
	}
	// Only the test's independent recovery authority authorizes this exact new
	// image; neither an error classification nor the database alone does so.
	f.anchor = protocolv4.NamespaceContinuityVersion{Revision: v.Revision + 1, Digest: sha256.Sum256(second)}
	closeSQLite(t, h.store)
	h, err = f.openHistory(false)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, len(first))
	got, n, err := h.LoadNamespace(context.Background(), dst)
	if err != nil || got != f.anchor || !bytes.Equal(dst[:n], second) {
		t.Fatal("lost original committed history", err)
	}
}

func TestSQLiteNamespaceReopenRejectsCorruptEnvelopeBeforeEpochWrite(t *testing.T) {
	for _, mutation := range []string{"digest", "shape", "chunk_length"} {
		t.Run(mutation, func(t *testing.T) {
			f := newSQLiteNamespaceFixture(t)
			h, err := f.openHistory(true)
			if err != nil {
				t.Fatal(err)
			}
			wire := f.record(70000, 17)
			f.anchor, err = h.CommitNamespace(context.Background(), protocolv4.NamespaceContinuityVersion{}, wire)
			if err != nil {
				t.Fatal(err)
			}
			closeSQLite(t, h.store)
			h, err = f.openHistory(false)
			if err != nil {
				t.Fatal("valid chunked reopen", err)
			}
			switch mutation {
			case "digest":
				wrong := [32]byte{99}
				err = h.store.exec("UPDATE manifest SET snapshot_digest=?1", named(1, wrong[:]))
			case "shape":
				wire[0] ^= 1
				digest := sha256.Sum256(wire)
				err = h.store.exec("UPDATE chunks SET data=?1 WHERE ordinal=0", named(1, wire[:65536]))
				if err == nil {
					err = h.store.exec("UPDATE manifest SET snapshot_digest=?1", named(1, digest[:]))
				}
			case "chunk_length":
				// Keep aggregate count/bytes unchanged while moving one byte
				// across the fixed chunk boundary.
				err = h.store.exec("UPDATE chunks SET data=?1 WHERE ordinal=0", named(1, wire[:65535]))
				if err == nil {
					err = h.store.exec("UPDATE chunks SET data=?1 WHERE ordinal=1", named(1, wire[65535:]))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			closeSQLite(t, h.store)
			before, err := os.ReadFile(f.backing.path)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := f.openHistory(false)
			if opened != nil {
				t.Fatal("corrupt namespace returned owner")
			}
			projection := storageFormatProjection(t, err)
			if projection.Reason != StorageFormatState || projection.ObservedRevision != (StorageRevision{Known: true, Value: 1}) {
				t.Fatal(projection)
			}
			after, err := os.ReadFile(f.backing.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal rewrote namespace history", err)
			}
		})
	}
}
