package ledgerv4

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const executionContentHeadsSQL = `CREATE TABLE content_heads (key BLOB PRIMARY KEY CHECK(length(key)=193), admitted BLOB NOT NULL CHECK(length(admitted)=8), items INTEGER NOT NULL CHECK(items>=0), bytes INTEGER NOT NULL CHECK(bytes>=0)) STRICT, WITHOUT ROWID`
const executionContentItemsSQL = `CREATE TABLE content_items (key BLOB NOT NULL CHECK(length(key)=193), position BLOB NOT NULL CHECK(length(position) BETWEEN 1 AND 256), committed BLOB NOT NULL CHECK(length(committed)=8), expires BLOB NOT NULL CHECK(length(expires)=8), bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND 1048576), digest BLOB NOT NULL CHECK(length(digest)=32), deleted INTEGER NOT NULL CHECK(deleted IN (0,1)), payload BLOB NOT NULL CHECK(length(payload)<=1048576), PRIMARY KEY(key,position)) STRICT, WITHOUT ROWID`

var ErrContentCommitUnknown = errors.New("ledgerv4: content commit unconfirmed")

// SQLiteContentObservation describes an explicit saved position. Found=false
// means this live history has no completed save at that position. It never
// means the execution completed, or the transport delivered an item. Expired
// positions remain tombstones until original history GC, preventing refresh.
type SQLiteContentObservation struct {
	Found, Available, Expired  bool
	CommittedAtMS, ExpiresAtMS uint64
	Bytes                      uint32
	Digest                     [32]byte
}

// SupportsContent is a finite local registration check. The trusted method
// supplies its understood definition digest; a peer cannot install one. The
// store reserves each possible operation's complete finite disk promise at
// construction, before any execution can be admitted.
func (e *SQLiteExecutions) SupportsContent(p protocolv4.ServiceContractPolicy) bool {
	if e == nil || !p.RetainedContent || p.Semantics != 1 || p.Shape != 1 || p.ExecutionMode != 1 || p.Content.RetentionOrigin > 1 || p.Content.RetentionMS == 0 || p.Content.MaxItems == 0 || p.Content.MaxBytes == 0 || p.Content.MaxItems > uint64(e.config.ContentItemsPerOperation) || p.Content.MaxBytes > e.config.ContentBytesPerOperation || e.config.ContentItemBytes == 0 {
		return false
	}
	for _, m := range e.config.Methods {
		if m.Type == p.Type && m.ContentDefinition != ([32]byte{}) && m.ContentDefinition == p.Content.Definition {
			return true
		}
	}
	return false
}

func (e *SQLiteExecutions) contentHead(key []byte) (admitted, items, bytes uint64, err error) {
	err = e.store.readOne("SELECT CASE WHEN length(admitted)=8 THEN admitted ELSE NULL END,items,bytes FROM content_heads WHERE key=?1", 3, func(values []driver.Value) error {
		var readErr error
		admitted, readErr = readSQLiteUint(values[0])
		i, iok := values[1].(int64)
		b, bok := values[2].(int64)
		if readErr != nil || !iok || !bok || i < 0 || b < 0 || uint64(i) > uint64(e.config.ContentItemsPerOperation) || uint64(b) > e.config.ContentBytesPerOperation {
			return ErrStorageFormat
		}
		items, bytes = uint64(i), uint64(b)
		return nil
	}, named(1, key))
	return
}

func (e *SQLiteExecutions) contentItem(key, position []byte) (o SQLiteContentObservation, err error) {
	err = e.store.readOne("SELECT CASE WHEN length(committed)=8 THEN committed ELSE NULL END,CASE WHEN length(expires)=8 THEN expires ELSE NULL END,bytes,CASE WHEN length(digest)=32 THEN digest ELSE NULL END,deleted,length(payload) FROM content_items WHERE key=?1 AND position=?2", 6, func(values []driver.Value) error {
		commit, ce := readSQLiteUint(values[0])
		expiry, ee := readSQLiteUint(values[1])
		n, nok := values[2].(int64)
		digest, dok := values[3].([]byte)
		deleted, xok := values[4].(int64)
		payload, pok := values[5].(int64)
		if ce != nil || ee != nil || !nok || n < 0 || n > int64(e.config.ContentItemBytes) || !dok || len(digest) != 32 || !xok || deleted < 0 || deleted > 1 || !pok || deleted == 0 && payload != n || deleted == 1 && payload != 0 || expiry == 0 {
			return ErrStorageFormat
		}
		o = SQLiteContentObservation{Found: true, CommittedAtMS: commit, ExpiresAtMS: expiry, Bytes: uint32(n), Expired: deleted == 1}
		copy(o.Digest[:], digest)
		return nil
	}, named(1, key), named(2, position))
	if errors.Is(err, io.EOF) {
		return SQLiteContentObservation{}, nil
	}
	if err != nil {
		return SQLiteContentObservation{}, err
	}
	return o, nil
}

func (e *SQLiteExecutions) contentPolicy(key []byte, r storedExecution) (p protocolv4.ServiceContractPolicy, err error) {
	n, err := e.readTerms(key)
	if err != nil {
		return p, err
	}
	c, err := e.codec.Decode(e.contract[:n])
	if err != nil {
		return p, err
	}
	defer c.Release()
	p, err = e.checkContract(c)
	if err == nil && (p.Digest != r.contract || !e.SupportsContent(p)) {
		err = ErrExecutionContract
	}
	return p, err
}

// SaveContent is explicit application retention by the original running
// streaming execution. Position is the bounded encoding specified by the
// trusted application definition, never an implicit transport offset. Exact
// duplicates preserve the original commit time; different bytes conflict.
// No unconfirmed transaction can grant an Available observation.
func (w *SQLiteExecutionWork) SaveContent(ctx context.Context, position, payload []byte, guard func() error) (out SQLiteContentObservation, err error) {
	if err = w.acquire(ctx, false); err != nil {
		return out, err
	}
	defer w.end()
	e := w.store
	if !w.entered || w.finished || guard == nil || len(position) == 0 || len(position) > 256 || len(payload) > len(e.content) {
		return out, ErrOwner
	}
	if w.contentUncertain {
		return out, ErrContentCommitUnknown
	}
	var location [256]byte
	copy(location[:], position)
	position = location[:len(position)]
	copy(e.content, payload)
	payload = e.content[:len(payload)]
	defer clear(payload)
	digest := sha256.Sum256(payload)
	check := func() error {
		if err := e.check(guard); err != nil {
			return err
		}
		if err := w.reservation.Check(); err != nil {
			return err
		}
		if err := w.deadline.Check(); err != nil {
			return err
		}
		return w.run.Check()
	}
	attempted := false
	err = e.store.writeTransaction(ctx, check, func() error {
		r, err := w.record()
		if err != nil {
			return err
		}
		if !r.Found || !r.WorkActive || !r.Dispatched || !r.StreamMetadataOnly || r.State != SQLiteExecutionExecuting {
			return ErrOwner
		}
		if r.CancelRequested {
			return timev4.ErrCancelled
		}
		p, err := e.contentPolicy(w.key[:], r)
		if err != nil {
			return err
		}
		admitted, items, total, err := e.contentHead(w.key[:])
		if err != nil {
			return err
		}
		o, err := e.contentItem(w.key[:], position)
		if err != nil {
			return err
		}
		now, err := e.config.Clock.Sample()
		if err != nil {
			return err
		}
		if o.Found {
			if o.Bytes != uint32(len(payload)) || o.Digest != digest {
				return ErrConflict
			}
			o.Expired = o.Expired || now.RetainedThrough(o.ExpiresAtMS)
			o.Available = !o.Expired && now.ValidBefore(o.ExpiresAtMS)
			out = o
			return nil
		}
		if items >= p.Content.MaxItems || total > p.Content.MaxBytes || uint64(len(payload)) > p.Content.MaxBytes-total {
			return ErrCapacity
		}
		origin := admitted
		if p.Content.RetentionOrigin == 1 {
			origin = now.UpperMS
		}
		if p.Content.RetentionMS > math.MaxUint64-origin {
			return ErrConfiguration
		}
		expires := origin + p.Content.RetentionMS
		if !now.ValidBefore(expires) {
			return ErrExecutionResultExpired
		}
		attempted = true
		if err = e.store.exec("INSERT INTO content_items VALUES (?1,?2,?3,?4,?5,?6,0,coalesce(?7,x''))", named(1, w.key[:]), named(2, position), named(3, sqliteUint(now.UpperMS)), named(4, sqliteUint(expires)), named(5, int64(len(payload))), named(6, digest[:]), named(7, payload)); err != nil {
			return err
		}
		if err = e.store.exec("UPDATE content_heads SET items=items+1,bytes=bytes+?1 WHERE key=?2", named(1, int64(len(payload))), named(2, w.key[:])); err != nil {
			return err
		}
		out = SQLiteContentObservation{Found: true, Available: true, CommittedAtMS: now.UpperMS, ExpiresAtMS: expires, Bytes: uint32(len(payload)), Digest: digest}
		return nil
	})
	if err != nil {
		w.contentUncertain = w.contentUncertain || attempted
		return SQLiteContentObservation{}, err
	}
	return out, nil
}

// ReadContent uses a newly authorized exact original operation and copies only
// one bounded position into the original reader's admitted destination. A
// missing history cannot become proof that a position was never saved.
func (e *SQLiteExecutions) ReadContent(ctx context.Context, q SQLiteExecutionRequest, position, dst []byte, readerType uint32, guard func() error) (out SQLiteContentObservation, n int, err error) {
	if guard == nil || len(position) == 0 || len(position) > 256 {
		return out, 0, ErrConfiguration
	}
	key, err := e.encodeKey(q.Key)
	if err != nil {
		return out, 0, err
	}
	if err = e.store.begin(ctx); err != nil {
		return out, 0, err
	}
	defer e.store.end()
	if err = e.check(guard); err != nil {
		return out, 0, err
	}
	if err = e.store.checkFence(); err != nil {
		return out, 0, err
	}
	r, err := e.readExecution(key[:])
	if err != nil {
		return out, 0, err
	}
	if err = executionMatches(r, q); err != nil {
		return out, 0, err
	}
	if !r.Found {
		return out, 0, ErrExecutionHistoryUnknown
	}
	p, err := e.contentPolicy(key[:], r)
	if err != nil {
		return out, 0, err
	}
	if readerType == 0 || e.ContentReadType(p.Type) != readerType {
		return out, 0, ErrExecutionContract
	}
	out, err = e.contentItem(key[:], position)
	if err != nil {
		return out, 0, err
	}
	if out.Found {
		now, err := e.config.Clock.Sample()
		if err != nil {
			return SQLiteContentObservation{}, 0, err
		}
		out.Expired = out.Expired || now.RetainedThrough(out.ExpiresAtMS)
		out.Available = !out.Expired && now.ValidBefore(out.ExpiresAtMS)
		if out.Available {
			if uint64(len(dst)) < uint64(out.Bytes) {
				return SQLiteContentObservation{}, 0, ErrCapacity
			}
			n, err = e.readBoundedBlob("SELECT length(payload),CASE WHEN length(payload)<=?3 THEN payload ELSE NULL END FROM content_items WHERE key=?1 AND position=?2 AND deleted=0", dst, named(1, key[:]), named(2, position), named(3, int64(out.Bytes)))
			if err != nil || n != int(out.Bytes) || sha256.Sum256(dst[:n]) != out.Digest {
				clear(dst[:n])
				return SQLiteContentObservation{}, 0, errors.Join(ErrStorageFormat, err)
			}
		}
	}
	// The sole provider transaction slot still protects this capture while
	// current authorization and trusted time are checked after the copy.
	if err = ctx.Err(); err == nil {
		err = e.check(guard)
	}
	if err == nil && out.Available {
		var now timev4.Sample
		now, err = e.config.Clock.Sample()
		if err == nil && !now.ValidBefore(out.ExpiresAtMS) {
			out.Available = false
			out.Expired = now.RetainedThrough(out.ExpiresAtMS)
			clear(dst[:n])
			n = 0
		}
	}
	if err != nil {
		clear(dst[:n])
		return SQLiteContentObservation{}, 0, err
	}
	return out, n, nil
}

// Payload reclamation preserves the fixed position, digest and first commit
// time. Counters include tombstones, so repeated saves cannot refill a bounded
// lifetime archive indefinitely. Live promises pin the original history.
func (e *SQLiteExecutions) collectContent(key []byte, lower uint64) (bool, error) {
	if err := e.store.exec("UPDATE content_items SET payload=x'',deleted=1 WHERE key=?1 AND expires<=?2 AND deleted=0", named(1, key), named(2, sqliteUint(lower))); err != nil {
		return false, err
	}
	n, err := e.store.scalar("SELECT count(*) FROM content_items WHERE key=?1 AND deleted=0", named(1, key))
	if err != nil {
		return false, err
	}
	count, ok := n.(int64)
	if !ok || count < 0 || uint64(count) > uint64(e.config.ContentItemsPerOperation) {
		return false, ErrStorageFormat
	}
	return count != 0, nil
}

// ContentReadType is the existing trusted local method that interprets this
// archive. It is a registration selector and grants no read authorization.
func (e *SQLiteExecutions) ContentReadType(typeID uint32) uint32 {
	if e == nil {
		return 0
	}
	for _, m := range e.config.Methods {
		if m.Type == typeID {
			return m.ContentReadType
		}
	}
	return 0
}
