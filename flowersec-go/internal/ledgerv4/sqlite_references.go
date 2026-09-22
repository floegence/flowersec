package ledgerv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrReferenceExpired = errors.New("ledgerv4: local operation reference expired")

// SQLiteReferenceConfig is independent from execution and spend history. This
// store saves query locators only; it never stores payload, keys or dispatch
// rights. MaxRecords comes from SQLiteLimits; concurrency is exactly one
// synchronous provider call, with no waiting queue. Collection is explicit.
type SQLiteReferenceConfig struct {
	Root                  *resourcev4.Root
	Owner                 resourcev4.OwnerKey
	Accounts              []resourcev4.Account
	Clock                 *timev4.Clock
	Domain                string
	MaxBytes, RetentionMS uint64
}

type SQLiteReferences struct {
	store          *SQLiteStore
	config         SQLiteReferenceConfig
	codec          *protocolv4.OperationReferenceCodec
	wire, existing [2048]byte
	gc             [16][32]byte
}

func SQLiteReferencesCharge(l SQLiteLimits, c SQLiteReferenceConfig) (resourcev4.Vector, error) {
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return base, err
	}
	if c.Root == nil || c.Clock == nil || !validBusinessIdentifier(c.Domain) || c.MaxBytes == 0 || c.MaxBytes > uint64(l.MaxRecords)*2048 || c.RetentionMS == 0 || l.MaxRecordBytes < 2048 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge {
		return resourcev4.Vector{}, ErrConfiguration
	}
	if uint64(l.MaxPages) < 16+4*(uint64(l.MaxRecords)+1) {
		return resourcev4.Vector{}, ErrCapacity
	}
	n, err := protocolv4.OperationReferenceCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: n + uint64(unsafe.Sizeof(SQLiteReferences{})) + 128 + uint64(len(c.Accounts))*uint64(unsafe.Sizeof(resourcev4.Account{})) + 4*uint64(unsafe.Sizeof(protocolv4.OperationReference{})), resourcev4.Items: 1})
}

func CreateSQLiteReferences(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteReferenceConfig, reservation, environment resourcev4.Reference) (*SQLiteReferences, error) {
	return openSQLiteReferences(ctx, backing, identity, continuity, c, reservation, environment, true)
}
func OpenSQLiteReferences(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteReferenceConfig, reservation, environment resourcev4.Reference) (*SQLiteReferences, error) {
	return openSQLiteReferences(ctx, backing, identity, continuity, c, reservation, environment, false)
}
func openSQLiteReferences(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteReferenceConfig, reservation, environment resourcev4.Reference, create bool) (*SQLiteReferences, error) {
	if err := reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	s, err := openSQLitePurpose(ctx, backing, identity, continuity, reservation, environment, create, nil, &c)
	if s == nil {
		return nil, err
	}
	if s.references == nil {
		s.references = &SQLiteReferences{store: s}
	}
	return s.references, err
}
func newSQLiteReferences(s *sqliteStore, c SQLiteReferenceConfig) (*SQLiteReferences, error) {
	codec, err := protocolv4.NewOperationReferenceCodec()
	if err != nil {
		return nil, err
	}
	c.Domain = strings.Clone(c.Domain)
	c.Accounts = append([]resourcev4.Account(nil), c.Accounts...)
	return &SQLiteReferences{store: &SQLiteStore{s}, config: c, codec: codec}, nil
}

// The local key includes the complete stable operation identity. The saved
// bytes separately bind request/contract/semantics and are compared exactly;
// a conflicting reference cannot create another entry for the same operation.
func referenceStorageKey(ref protocolv4.OperationReference) [32]byte {
	t := ref.Target()
	h := sha256.New()
	h.Write([]byte("flowersec/local-operation-reference/1"))
	var size [8]byte
	for _, s := range []string{ref.TargetDomain(), t.Tenant, t.Audience, t.Namespace, t.Subject} {
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		h.Write(size[:])
		h.Write([]byte(s))
	}
	h.Write(t.Authority[:])
	h.Write(t.Operation[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func (r *SQLiteReferences) check() error {
	for _, ref := range []resourcev4.Reference{r.store.reservation, r.store.environment, r.store.disk} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

// Save returns nil only after exact create-or-compare and durable COMMIT. It
// never treats a queued task, a successful write before commit, or a lost
// commit response as confirmation. The caller owns the original handoff gate.
func (r *SQLiteReferences) Save(ctx context.Context, ref protocolv4.OperationReference) error {
	if r == nil || r.store == nil || !ref.Valid() || ref.TargetDomain() != r.config.Domain {
		return ErrConfiguration
	}
	if err := r.store.begin(ctx); err != nil {
		return err
	}
	defer r.store.end()
	n, err := r.codec.Export(r.wire[:], ref)
	if err != nil {
		return err
	}
	defer clear(r.wire[:])
	defer clear(r.existing[:])
	key := referenceStorageKey(ref)
	if key == ([32]byte{}) {
		return ErrConfiguration
	}
	return r.store.writeTransaction(ctx, r.check, func() error {
		previous, expires, found, err := r.readRow(key)
		if err != nil {
			return err
		}
		now, err := r.config.Clock.Sample()
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(r.existing[:previous], r.wire[:n]) {
				return ErrConflict
			}
			if !now.ValidBefore(expires) {
				return ErrReferenceExpired
			}
			return nil
		}
		if r.config.RetentionMS > math.MaxUint64-now.UpperMS {
			return ErrConfiguration
		}
		var values [2]driver.Value
		if err = r.store.one("SELECT records,bytes FROM manifest WHERE id=1", values[:]); err != nil {
			return err
		}
		count, cok := values[0].(int64)
		total, tok := values[1].(int64)
		if !cok || !tok || count < 0 || total < 0 || uint64(total) > r.config.MaxBytes || count > int64(r.store.backing.limits.MaxRecords) {
			return ErrStorageFormat
		}
		if count == int64(r.store.backing.limits.MaxRecords) || uint64(n) > r.config.MaxBytes-uint64(total) {
			return ErrCapacity
		}
		if err = r.store.exec("INSERT INTO refs VALUES (?1,?2,?3,?4)", named(1, key[:]), named(2, sqliteUint(now.UpperMS)), named(3, sqliteUint(now.UpperMS+r.config.RetentionMS)), named(4, r.wire[:n])); err != nil {
			return err
		}
		return r.store.exec("UPDATE manifest SET records=records+1,bytes=bytes+?1 WHERE id=1", named(1, int64(n)))
	})
}

// readRow copies all provider bytes before stepping or releasing its cursor.
// The returned size refers only to this store's original bounded workspace.
func (r *SQLiteReferences) readRow(key [32]byte) (n int, expires uint64, found bool, err error) {
	rows, err := r.store.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(saved)=8 THEN saved ELSE NULL END,CASE WHEN length(expires)=8 THEN expires ELSE NULL END,length(reference),CASE WHEN length(reference)<=2048 THEN reference ELSE NULL END FROM refs WHERE key=?1", []driver.NamedValue{named(1, key[:])})
	if err != nil {
		return 0, 0, false, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [4]driver.Value
	if err = rows.Next(values[:]); errors.Is(err, io.EOF) {
		return 0, 0, false, nil
	} else if err != nil {
		return 0, 0, false, err
	}
	saved, se := readSQLiteUint(values[0])
	expires, err = readSQLiteUint(values[1])
	length, lok := values[2].(int64)
	body, bok := values[3].([]byte)
	if se != nil || err != nil || r.config.RetentionMS > math.MaxUint64-saved || expires != saved+r.config.RetentionMS || !lok || !bok || length < 1 || length > 2048 || length != int64(len(body)) {
		return 0, 0, false, ErrStorageFormat
	}
	n = copy(r.existing[:], body)
	ref, err := r.codec.Import(r.existing[:n], r.config.Domain)
	if err != nil || referenceStorageKey(ref) != key {
		return 0, 0, false, ErrStorageFormat
	}
	if err = rows.Next(values[:]); err != io.EOF {
		return 0, 0, false, ErrStorageFormat
	}
	return n, expires, true, nil
}

// Load returns only an immutable locator. It never reconstructs Start or
// accesses execution history. The supplied reference is an exact selector;
// imported values still require separately authorized queries afterward.
func (r *SQLiteReferences) Load(ctx context.Context, selector protocolv4.OperationReference) (protocolv4.OperationReference, bool, error) {
	if r == nil || r.store == nil || !selector.Valid() || selector.TargetDomain() != r.config.Domain {
		return protocolv4.OperationReference{}, false, ErrConfiguration
	}
	if err := r.store.begin(ctx); err != nil {
		return protocolv4.OperationReference{}, false, err
	}
	defer r.store.end()
	defer clear(r.existing[:])
	if err := r.store.checkFence(); err != nil {
		return protocolv4.OperationReference{}, false, err
	}
	n, expires, found, err := r.readRow(referenceStorageKey(selector))
	if err != nil || !found {
		return protocolv4.OperationReference{}, false, err
	}
	out, err := r.codec.Import(r.existing[:n], r.config.Domain)
	if err != nil {
		return protocolv4.OperationReference{}, false, err
	}
	if out != selector {
		return protocolv4.OperationReference{}, false, ErrConflict
	}
	now, err := r.config.Clock.Sample()
	if err != nil {
		return protocolv4.OperationReference{}, false, err
	}
	if !now.ValidBefore(expires) {
		return protocolv4.OperationReference{}, false, ErrReferenceExpired
	}
	if err = ctx.Err(); err == nil {
		err = r.check()
	}
	if err != nil {
		return protocolv4.OperationReference{}, false, err
	}
	return out, true, nil
}

func (r *SQLiteReferences) CheckBinding(domain string, backing resourcev4.Reference) error {
	if r == nil || r.store == nil || domain != r.config.Domain {
		return ErrOwner
	}
	if err := backing.CheckSameEnvironment(r.store.reservation); err != nil {
		return err
	}
	return r.check()
}
func (r *SQLiteReferences) Close() {
	if r != nil && r.store != nil {
		r.store.Close()
	}
}
func (r *SQLiteReferences) WaitCleanup(ctx context.Context) error {
	if r == nil || r.store == nil {
		return ErrOwner
	}
	return r.store.WaitCleanup(ctx)
}
func (r *SQLiteReferences) Retire() error {
	if r == nil || r.store == nil {
		return ErrOwner
	}
	return r.store.Retire()
}
func (*SQLiteReferences) String() string               { return "Flowersec.SQLiteReferences" }
func (*SQLiteReferences) GoString() string             { return "Flowersec.SQLiteReferences" }
func (*SQLiteReferences) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
