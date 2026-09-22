package ledgerv4

import (
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func (e *SQLiteExecutions) verifyContentCounts() error {
	for _, q := range []struct {
		sql     string
		maximum uint64
	}{
		{"SELECT count(*) FROM content_heads", uint64(e.store.backing.limits.MaxRecords)},
		{"SELECT count(*) FROM content_items", uint64(e.store.backing.limits.MaxRecords) * uint64(e.config.ContentItemsPerOperation)},
		{"SELECT count(*) FROM content_heads h LEFT JOIN executions e ON e.key=h.key WHERE e.key IS NULL", 0},
		{"SELECT count(*) FROM content_items i LEFT JOIN content_heads h ON h.key=i.key WHERE h.key IS NULL", 0},
	} {
		value, err := e.store.scalar(q.sql)
		if err != nil {
			return err
		}
		n, ok := value.(int64)
		if !ok || n < 0 || uint64(n) > q.maximum {
			return ErrStorageFormat
		}
	}
	return nil
}

// Each restart verifies the original policy, fixed retention origin, indexes,
// counts and real content bytes with the same bounded workspace. Continuity
// proof is still required; valid archive rows never recreate a work handle.
func (e *SQLiteExecutions) verifyContentRow(key []byte, p protocolv4.ServiceContractPolicy) error {
	admitted, items, total, err := e.contentHead(key)
	if !p.RetainedContent {
		if !errors.Is(err, io.EOF) {
			return ErrStorageFormat
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !e.SupportsContent(p) || items > p.Content.MaxItems || total > p.Content.MaxBytes || p.Content.RetentionMS > math.MaxUint64-admitted {
		return ErrStorageFormat
	}
	var cursor, position [256]byte
	cursorSize := 0
	var count, bytes uint64
	defer clear(e.content)
	for {
		n, err := e.readBoundedBlob("SELECT length(position),CASE WHEN length(position) BETWEEN 1 AND 256 THEN position ELSE NULL END FROM content_items WHERE key=?1 AND position>?2 ORDER BY position LIMIT 1", position[:], named(1, key), named(2, cursor[:cursorSize]))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if n == 0 || count >= items {
			return ErrStorageFormat
		}
		o, err := e.contentItem(key, position[:n])
		if err != nil {
			return err
		}
		origin := admitted
		if p.Content.RetentionOrigin == 1 {
			origin = o.CommittedAtMS
		}
		if !o.Found || o.CommittedAtMS < admitted || p.Content.RetentionMS > math.MaxUint64-origin || o.ExpiresAtMS != origin+p.Content.RetentionMS || uint64(o.Bytes) > total-bytes {
			return ErrStorageFormat
		}
		if !o.Expired {
			payloadBytes, err := e.readBoundedBlob("SELECT length(payload),CASE WHEN length(payload)<=?3 THEN payload ELSE NULL END FROM content_items WHERE key=?1 AND position=?2", e.content, named(1, key), named(2, position[:n]), named(3, int64(e.config.ContentItemBytes)))
			if err != nil {
				return err
			}
			if payloadBytes != int(o.Bytes) || sha256.Sum256(e.content[:payloadBytes]) != o.Digest {
				return ErrStorageFormat
			}
		}
		count++
		bytes += uint64(o.Bytes)
		cursorSize = copy(cursor[:], position[:n])
	}
	if count != items || bytes != total {
		return ErrStorageFormat
	}
	return e.store.readOne("SELECT CASE WHEN length(facts)=104 THEN facts ELSE NULL END FROM executions WHERE key=?1", 1, func(facts []driver.Value) error {
		r, err := decodeExecutionFacts(facts[0])
		if err != nil || admitted >= r.DeadlineAtMS {
			return ErrStorageFormat
		}
		return nil
	}, named(1, key))
}
