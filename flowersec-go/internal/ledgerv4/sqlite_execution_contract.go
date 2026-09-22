package ledgerv4

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type executionContract struct {
	revision     uint64
	enabled      bool
	offers       [8]timev4.Interval
	count, bytes int
}

// InstallContract changes one exact contract registration with a durable CAS.
// guard is trusted, finite SDK authorization/registration work: no I/O, user
// callback, or store reentry. Its metadata must have original admitted backing.
// Each Offer retains its own interval; overlapping windows are never joined.
func (e *SQLiteExecutions) InstallContract(ctx context.Context, expectedRevision uint64, canonical []byte, offers []timev4.Interval, enabled bool, guard func() error) (revision uint64, err error) {
	if e == nil || e.store == nil || guard == nil || len(canonical) == 0 || len(canonical) > 8192 || len(offers) > 8 || expectedRevision == math.MaxUint64 {
		return 0, ErrConfiguration
	}
	if err = e.store.begin(ctx); err != nil {
		return 0, err
	}
	defer e.store.end()
	if err = guard(); err != nil {
		return 0, err
	}
	n := copy(e.contract[:], canonical)
	c, err := e.codec.Decode(e.contract[:n])
	if err != nil {
		return 0, err
	}
	defer c.Release()
	p, err := e.checkContract(c)
	if err != nil {
		return 0, err
	}
	var windows [128]byte
	for i, o := range offers {
		if o.LowerMS >= o.UpperMS {
			return 0, ErrConfiguration
		}
		binary.BigEndian.PutUint64(windows[i*16:], o.LowerMS)
		binary.BigEndian.PutUint64(windows[i*16+8:], o.UpperMS)
	}
	err = e.store.writeTransaction(ctx, guard, func() error {
		current, err := e.registryRevision()
		if err != nil {
			return err
		}
		if current != expectedRevision {
			return ErrConflict
		}
		count, err := e.store.scalar("SELECT count(*) FROM contracts WHERE digest=?1", named(1, p.Digest[:]))
		if err != nil {
			return err
		}
		if count == int64(0) {
			total, err := e.store.scalar("SELECT count(*) FROM contracts WHERE type=?1", named(1, int64(p.Type)))
			if err != nil {
				return err
			}
			n, ok := total.(int64)
			if !ok || n < 0 {
				return ErrStorageFormat
			}
			if n >= 8 {
				return ErrCapacity
			}
		} else if count != int64(1) {
			return ErrStorageFormat
		} else {
			original, err := e.readContract(p.Digest)
			if err != nil {
				return err
			}
			if original.count != 0 {
				now, err := e.config.Clock.Sample()
				if err != nil {
					return err
				}
				for _, old := range original.offers[:original.count] {
					if now.RetainedThrough(old.UpperMS) {
						continue
					}
					retained := false
					for _, next := range offers {
						retained = retained || old == next
					}
					if !enabled || !retained {
						return ErrOwner
					}
				}
			}
		}
		on := int64(0)
		if enabled {
			on = 1
		}
		revision = current + 1
		if err = e.store.exec("INSERT INTO contracts VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(digest) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,offers=excluded.offers", named(1, p.Digest[:]), named(2, sqliteUint(revision)), named(3, int64(p.Type)), named(4, on), named(5, e.contract[:n]), named(6, windows[:len(offers)*16])); err != nil {
			return err
		}
		return e.store.exec("UPDATE manifest SET registry_revision=?1 WHERE id=1", named(1, sqliteUint(revision)))
	})
	if err != nil {
		return 0, err
	}
	return revision, nil
}

func (e *SQLiteExecutions) checkContract(c *protocolv4.ServiceContract) (protocolv4.ServiceContractPolicy, error) {
	p, err := c.Policy()
	if err != nil {
		return p, err
	}
	if p.Namespace != e.config.Service.Namespace || p.Semantics != 1 || p.ExecutionMode != 1 || p.Checkpoint && e.recovery == nil || p.RetainedContent && !e.SupportsContent(p) || p.Shape == 0 && p.MaxResponseBytes > e.store.backing.limits.MaxRecordBytes {
		return p, ErrExecutionContract
	}
	shape, err := c.MethodShapeDigest()
	if err != nil {
		return p, err
	}
	for _, m := range e.config.Methods {
		if m.Type == p.Type && m.Shape == shape {
			return p, nil
		}
	}
	return p, ErrExecutionContract
}

func (e *SQLiteExecutions) registryRevision() (uint64, error) {
	var b [8]byte
	n, err := e.readBoundedBlob("SELECT length(registry_revision),CASE WHEN length(registry_revision)=8 THEN registry_revision ELSE NULL END FROM manifest WHERE id=1", b[:])
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, ErrStorageFormat
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func (e *SQLiteExecutions) readContract(digest [32]byte) (r executionContract, err error) {
	rows, err := e.store.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(revision)=8 THEN revision ELSE NULL END,enabled,length(terms),CASE WHEN length(terms)<=8192 THEN terms ELSE NULL END,CASE WHEN length(offers)<=128 THEN offers ELSE NULL END FROM contracts WHERE digest=?1", []driver.NamedValue{named(1, digest[:])})
	if err != nil {
		return r, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [5]driver.Value
	if err = rows.Next(values[:]); err == io.EOF {
		return r, ErrExecutionContract
	} else if err != nil {
		return r, err
	}
	r.revision, err = readSQLiteUint(values[0])
	on, ok := values[1].(int64)
	n, nok := values[2].(int64)
	terms, tok := values[3].([]byte)
	windows, wok := values[4].([]byte)
	if err != nil || r.revision == 0 || !ok || on < 0 || on > 1 || !nok || !tok || n < 1 || n > 8192 || n != int64(len(terms)) || !wok || len(windows) > 128 || len(windows)%16 != 0 {
		return executionContract{}, ErrStorageFormat
	}
	r.enabled = on == 1
	r.bytes = copy(e.contract[:], terms)
	r.count = len(windows) / 16
	for i := 0; i < r.count; i++ {
		r.offers[i] = timev4.Interval{LowerMS: binary.BigEndian.Uint64(windows[i*16:]), UpperMS: binary.BigEndian.Uint64(windows[i*16+8:])}
		if r.offers[i].LowerMS >= r.offers[i].UpperMS {
			return executionContract{}, ErrStorageFormat
		}
	}
	if err = rows.Next(values[:]); err != io.EOF {
		return executionContract{}, ErrStorageFormat
	}
	return r, nil
}

func (e *SQLiteExecutions) floor(authority [32]byte) (uint64, error) {
	var b [8]byte
	n, err := e.readBoundedBlob("SELECT length(floor),CASE WHEN length(floor)=8 THEN floor ELSE NULL END FROM domains WHERE authority=?1", b[:], named(1, authority[:]))
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, ErrStorageFormat
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func (r executionContract) admission(now timev4.Sample, cutoff uint64) bool {
	for _, o := range r.offers[:r.count] {
		if now.LowerMS >= o.LowerMS && now.UpperMS < cutoff && cutoff <= o.UpperMS {
			return true
		}
	}
	return false
}
