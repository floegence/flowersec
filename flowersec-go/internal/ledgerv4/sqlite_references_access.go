package ledgerv4

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// List copies at most sixteen existing query locators into caller-owned
// storage. Its opaque cursor only orders this local file; it is no credential
// or remote execution cursor. Each call scans at most len(dst) stored rows,
// including expired entries; next may advance even when no live row is copied.
func (r *SQLiteReferences) List(ctx context.Context, after [32]byte, dst []protocolv4.OperationReference) (n int, next [32]byte, err error) {
	if r == nil || r.store == nil || len(dst) == 0 || len(dst) > 16 {
		return 0, after, ErrConfiguration
	}
	if err = r.store.begin(ctx); err != nil {
		return 0, after, err
	}
	defer r.store.end()
	defer clear(r.existing[:])
	next = after
	defer func() {
		if err != nil {
			clear(dst[:n])
			n = 0
			next = after
		}
	}()
	if err = r.store.checkFence(); err != nil {
		return
	}
	now, err := r.config.Clock.Sample()
	if err != nil {
		return 0, after, err
	}
	for range len(dst) {
		key, found, e := r.nextKey(next)
		if e != nil {
			return n, next, e
		}
		if !found {
			break
		}
		next = key
		size, expires, present, e := r.readRow(key)
		if e != nil {
			return n, next, e
		}
		if !present {
			return n, next, ErrStorageFormat
		}
		if !now.ValidBefore(expires) {
			continue
		}
		ref, e := r.codec.Import(r.existing[:size], r.config.Domain)
		if e != nil {
			return n, next, e
		}
		dst[n] = ref
		n++
	}
	if err = ctx.Err(); err == nil {
		err = r.check()
	}
	return
}

// Collect removes one bounded page only after trusted time proves expiry.
// Deleting these local locators has no effect on service-side deduplication,
// retained results, authorization or an existing operation's Start rights.
func (r *SQLiteReferences) Collect(ctx context.Context) error {
	if r == nil || r.store == nil {
		return ErrOwner
	}
	if err := r.store.begin(ctx); err != nil {
		return err
	}
	defer r.store.end()
	defer clear(r.existing[:])
	defer clear(r.gc[:])
	now, err := r.config.Clock.Sample()
	if err != nil {
		return err
	}
	return r.store.writeTransaction(ctx, r.check, func() error {
		count, err := r.expiredKeys(now.LowerMS)
		if err != nil {
			return err
		}
		for _, key := range r.gc[:count] {
			n, expires, found, err := r.readRow(key)
			if err != nil {
				return err
			}
			if !found || !now.RetainedThrough(expires) {
				return ErrStorageFormat
			}
			if err = r.store.exec("DELETE FROM refs WHERE key=?1", named(1, key[:])); err != nil {
				return err
			}
			if err = r.store.changedOne(); err != nil {
				return err
			}
			if err = r.store.exec("UPDATE manifest SET records=records-1,bytes=bytes-?1 WHERE id=1", named(1, int64(n))); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *SQLiteReferences) expiredKeys(lower uint64) (count int, err error) {
	rows, err := r.store.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(key)=32 THEN key ELSE NULL END FROM refs WHERE expires<=?1 ORDER BY key LIMIT 16", []driver.NamedValue{named(1, sqliteUint(lower))})
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var v [1]driver.Value
	for {
		if err = rows.Next(v[:]); err == io.EOF {
			return count, nil
		} else if err != nil {
			return 0, err
		}
		key, ok := v[0].([]byte)
		if !ok || len(key) != 32 || count >= len(r.gc) {
			return 0, ErrStorageFormat
		}
		copy(r.gc[count][:], key)
		count++
	}
}

func (r *SQLiteReferences) Borrow(domain string, backing resourcev4.Reference) (resourcev4.Reference, error) {
	if err := r.CheckBinding(domain, backing); err != nil {
		return resourcev4.Reference{}, err
	}
	return r.store.reservation.Borrow()
}
