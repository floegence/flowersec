package ledgerv4

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"math"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// NamespaceRestoreAuthority independently attests that this exact snapshot is
// current under the supported storage recovery model. It is bounded local work
// without I/O, application callbacks or store reentry. It cannot derive freshness
// from the same SQLite file. Backup/disk rollback requires an external recovery
// anchor or trusted authority reconstruction; this adapter supplies neither.
type NamespaceRestoreAuthority interface {
	CheckNamespaceRestore(SQLiteIdentity, protocolv4.NamespaceContinuityScope, protocolv4.NamespaceContinuityVersion) error
}

type SQLiteNamespaceConfig struct {
	Scope   protocolv4.NamespaceContinuityScope
	Restore NamespaceRestoreAuthority
}

// SQLiteNamespaceHistory uses one explicit transaction group for one complete
// namespace. Fixed-size chunks permit large bounded State/trust histories
// without allocating an unbounded driver row. Manifest and all chunks change
// in one FULL synchronous transaction, never a partially published blob graph.
type SQLiteNamespaceHistory struct {
	store              *SQLiteStore
	config             SQLiteNamespaceConfig
	maximum            uint64
	configuration      [512]byte
	configurationBytes int
}

const namespaceChunkBytes = 65536

func SQLiteNamespaceHistoryCharge(l SQLiteLimits, c SQLiteNamespaceConfig) (resourcev4.Vector, error) {
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return base, err
	}
	if !validBusinessIdentifier(c.Scope.Tenant) || !validBusinessIdentifier(c.Scope.Authority) || c.Scope.Capacity == ([32]byte{}) || c.Restore == nil || l.MaxRecordBytes < namespaceChunkBytes {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n, err := protocolv4.NamespaceContinuityRecordBytes(c.Scope.Limits)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	chunks := (n + namespaceChunkBytes - 1) / namespaceChunkBytes
	// Old and new complete trees, overflow pages, metadata and fragmentation
	// coexist until the original COMMIT/checkpoint has actually returned.
	pages := 2*((n+sqlitePageBytes-1)/sqlitePageBytes+2*chunks) + 32
	if uint64(l.MaxRecords) < chunks || uint64(l.MaxPages) < pages {
		return resourcev4.Vector{}, ErrCapacity
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteNamespaceHistory{})) + uint64(unsafe.Sizeof(protocolv4.NamespaceContinuityRecord{})) + 8192, resourcev4.Items: 1})
}

func newSQLiteNamespaceHistory(s *sqliteStore, c SQLiteNamespaceConfig) (*SQLiteNamespaceHistory, error) {
	c.Scope.Tenant, c.Scope.Authority = strings.Clone(c.Scope.Tenant), strings.Clone(c.Scope.Authority)
	n, err := protocolv4.NamespaceContinuityRecordBytes(c.Scope.Limits)
	if err != nil {
		return nil, err
	}
	h := &SQLiteNamespaceHistory{store: &SQLiteStore{s}, config: c, maximum: n}
	w := admissionWriter{dst: h.configuration[:]}
	w.text(c.Scope.Tenant)
	w.text(c.Scope.Authority)
	w.bytes(c.Scope.Capacity[:])
	l := c.Scope.Limits
	for _, v := range []uint64{uint64(l.TrustConfigurations), uint64(l.TrustConfigBytes), l.StateBytes, l.FetchDurationMS, uint64(l.FetchAttempts)} {
		w.uint(v)
	}
	h.configurationBytes = w.n
	return h, w.err
}

func CreateSQLiteNamespaceHistory(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteNamespaceConfig, reservation, environment resourcev4.Reference) (*SQLiteNamespaceHistory, error) {
	return openSQLiteNamespaceHistory(ctx, backing, identity, continuity, c, reservation, environment, true)
}
func OpenSQLiteNamespaceHistory(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteNamespaceConfig, reservation, environment resourcev4.Reference) (*SQLiteNamespaceHistory, error) {
	return openSQLiteNamespaceHistory(ctx, backing, identity, continuity, c, reservation, environment, false)
}
func openSQLiteNamespaceHistory(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteNamespaceConfig, reservation, environment resourcev4.Reference, create bool) (*SQLiteNamespaceHistory, error) {
	s, err := openSQLitePurpose(ctx, backing, identity, continuity, reservation, environment, create, nil, nil, nil, nil, &c, nil)
	if s == nil {
		return nil, err
	}
	if s.namespace == nil {
		s.namespace = &SQLiteNamespaceHistory{store: s}
	}
	return s.namespace, err
}

func (h *SQLiteNamespaceHistory) CheckNamespaceScope(scope protocolv4.NamespaceContinuityScope) error {
	if h == nil || h.store == nil {
		return ErrConfiguration
	}
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	if h.store.closed {
		return ErrOwner
	}
	if scope != h.config.Scope {
		return ErrConfiguration
	}
	return nil
}

// CheckNamespaceContinuity delegates freshness to the independently admitted
// recovery authority. The SQLite snapshot remains only the complete facts;
// its revision/digest cannot attest that an older backup was not restored.
func (h *SQLiteNamespaceHistory) CheckNamespaceContinuity(ctx context.Context, scope protocolv4.NamespaceContinuityScope, version protocolv4.NamespaceContinuityVersion) error {
	if h == nil || h.store == nil || ctx == nil {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.CheckNamespaceScope(scope); err != nil {
		return err
	}
	return h.config.Restore.CheckNamespaceRestore(h.store.identity, scope, version)
}

func (h *SQLiteNamespaceHistory) LoadNamespace(ctx context.Context, dst []byte) (version protocolv4.NamespaceContinuityVersion, n int, err error) {
	if h == nil || h.store == nil {
		return version, 0, ErrConfiguration
	}
	if err = h.store.begin(ctx); err != nil {
		return version, 0, err
	}
	defer h.store.end()
	defer func() {
		if err != nil {
			clear(dst[:n])
			version, n = protocolv4.NamespaceContinuityVersion{}, 0
		}
	}()
	if err = h.store.exec("BEGIN DEFERRED"); err != nil {
		return version, 0, err
	}
	defer func() { err = errors.Join(err, h.store.exec("ROLLBACK")) }()
	if err = h.store.checkFence(); err != nil {
		return version, 0, err
	}
	if err = h.store.continuity.Check(h.store.identity, h.store.epoch, false); err != nil {
		return version, 0, err
	}
	var size uint64
	version, size, err = h.readVersion()
	if err != nil {
		return version, 0, err
	}
	if uint64(len(dst)) < size {
		return version, 0, ErrCapacity
	}
	if err = h.config.Restore.CheckNamespaceRestore(h.store.identity, h.config.Scope, version); err != nil {
		return version, 0, err
	}
	if err = h.readChunks(ctx, dst[:size]); err != nil {
		n = int(size)
		return version, n, err
	}
	n = int(size)
	if size == 0 {
		return version, 0, ErrStorageUnavailable
	}
	if sha256.Sum256(dst[:n]) != version.Digest {
		return version, n, ErrStorageFormat
	}
	if _, err = protocolv4.DecodeNamespaceContinuityRecord(dst[:n], h.config.Scope.Limits); err != nil {
		return version, n, ErrStorageFormat
	}
	if err = h.config.Restore.CheckNamespaceRestore(h.store.identity, h.config.Scope, version); err == nil {
		err = h.store.checkFence()
	}
	if err == nil {
		err = h.store.continuity.Check(h.store.identity, h.store.epoch, false)
	}
	if err == nil {
		err = ctx.Err()
	}
	return
}

func (h *SQLiteNamespaceHistory) CommitNamespace(ctx context.Context, expected protocolv4.NamespaceContinuityVersion, wire []byte) (out protocolv4.NamespaceContinuityVersion, err error) {
	if h == nil || h.store == nil || expected.Revision == math.MaxUint64 {
		return out, ErrConfiguration
	}
	if err = h.store.begin(ctx); err != nil {
		return out, err
	}
	defer h.store.end()
	if uint64(len(wire)) > h.maximum {
		return out, ErrCapacity
	}
	if _, err = protocolv4.DecodeNamespaceContinuityRecord(wire, h.config.Scope.Limits); err != nil {
		return out, ErrStorageFormat
	}
	next := protocolv4.NamespaceContinuityVersion{Revision: expected.Revision + 1, Digest: sha256.Sum256(wire)}
	err = h.store.writeTransaction(ctx, func() error { return h.store.continuity.Check(h.store.identity, h.store.epoch, false) }, func() error {
		current, _, e := h.readVersion()
		if e != nil {
			return e
		}
		if current != expected {
			return ErrConflict
		}
		chunks := (len(wire) + namespaceChunkBytes - 1) / namespaceChunkBytes
		for i := range chunks {
			if e = ctx.Err(); e != nil {
				return e
			}
			end := min((i+1)*namespaceChunkBytes, len(wire))
			if e = h.store.exec("INSERT INTO chunks (ordinal,data) VALUES (?1,?2) ON CONFLICT(ordinal) DO UPDATE SET data=excluded.data", named(1, int64(i)), named(2, wire[i*namespaceChunkBytes:end])); e != nil {
				return e
			}
		}
		if e = h.store.exec("DELETE FROM chunks WHERE ordinal>=?1", named(1, int64(chunks))); e != nil {
			return e
		}
		return h.store.exec("UPDATE manifest SET snapshot_revision=?1,snapshot_digest=?2,snapshot_bytes=?3 WHERE id=1", named(1, sqliteUint(next.Revision)), named(2, next.Digest[:]), named(3, int64(len(wire))))
	})
	if err != nil {
		return out, err
	}
	return next, nil
}

func (h *SQLiteNamespaceHistory) readVersion() (out protocolv4.NamespaceContinuityVersion, size uint64, err error) {
	err = h.store.readOne("SELECT CASE WHEN length(snapshot_revision)=8 THEN snapshot_revision ELSE NULL END,CASE WHEN length(snapshot_digest)=32 THEN snapshot_digest ELSE NULL END,snapshot_bytes FROM manifest WHERE id=1", 3, func(v []driver.Value) error {
		var e error
		out.Revision, e = readSQLiteUint(v[0])
		digest, ok := v[1].([]byte)
		n, nok := v[2].(int64)
		if e != nil || !ok || len(digest) != 32 || !nok || n < 0 || uint64(n) > h.maximum {
			return ErrStorageFormat
		}
		copy(out.Digest[:], digest)
		size = uint64(n)
		if out.Revision == 0 && (size != 0 || out.Digest != ([32]byte{})) || out.Revision != 0 && (size == 0 || out.Digest == ([32]byte{})) {
			return ErrStorageFormat
		}
		return nil
	})
	return
}

func (h *SQLiteNamespaceHistory) readChunks(ctx context.Context, dst []byte) error {
	count := (len(dst) + namespaceChunkBytes - 1) / namespaceChunkBytes
	rows, err := h.store.scalar("SELECT count(*) FROM chunks")
	if err != nil {
		return err
	}
	if rows != int64(count) {
		return ErrStorageFormat
	}
	for i := range count {
		if err = ctx.Err(); err != nil {
			return err
		}
		end := min((i+1)*namespaceChunkBytes, len(dst))
		err = h.store.readOne("SELECT CASE WHEN length(data)<=65536 THEN data ELSE NULL END FROM chunks WHERE ordinal=?1", 1, func(v []driver.Value) error {
			b, ok := v[0].([]byte)
			if !ok || len(b) != end-i*namespaceChunkBytes {
				return ErrStorageFormat
			}
			copy(dst[i*namespaceChunkBytes:end], b)
			return nil
		}, named(1, int64(i)))
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *SQLiteNamespaceHistory) Close() {
	if h != nil && h.store != nil {
		h.store.Close()
	}
}
func (h *SQLiteNamespaceHistory) WaitCleanup(ctx context.Context) error {
	if h == nil {
		return ErrConfiguration
	}
	return h.store.WaitCleanup(ctx)
}
func (h *SQLiteNamespaceHistory) Retire() error {
	if h == nil {
		return ErrConfiguration
	}
	return h.store.Retire()
}
func (h *SQLiteNamespaceHistory) clear() {
	h.config = SQLiteNamespaceConfig{}
	clear(h.configuration[:])
	h.configurationBytes = 0
}
func (*SQLiteNamespaceHistory) String() string               { return "Flowersec.SQLiteNamespaceHistory" }
func (*SQLiteNamespaceHistory) GoString() string             { return "Flowersec.SQLiteNamespaceHistory" }
func (*SQLiteNamespaceHistory) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var _ protocolv4.NamespaceContinuityStore = (*SQLiteNamespaceHistory)(nil)

// Initialization failures are never interpreted as empty or valid history.
func namespaceRollback(s *sqliteStore, err *error) {
	if *err != nil {
		*err = errors.Join(*err, s.exec("ROLLBACK"))
	}
}
