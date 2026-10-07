package ledgerv4

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// sqliteChunkReader retains only the current bounded driver row. The decoder
// consumes it synchronously before the cursor advances; no complete snapshot
// copy or current authorization owner is created by admission.
type sqliteChunkReader struct {
	rows           driver.Rows
	values         [2]driver.Value
	chunk          []byte
	size, consumed uint64
	ordinal        int64
}

func (r *sqliteChunkReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if len(r.chunk) == 0 {
		if r.consumed == r.size {
			return 0, io.EOF
		}
		if err := r.rows.Next(r.values[:]); err != nil {
			return 0, err
		}
		ordinal, ok := r.values[0].(int64)
		data, valid := r.values[1].([]byte)
		if !ok || ordinal != r.ordinal || !valid || uint64(len(data)) != min(uint64(namespaceChunkBytes), r.size-r.consumed) {
			return 0, ErrStorageFormat
		}
		r.ordinal++
		r.chunk = data
	}
	n := copy(dst, r.chunk)
	r.chunk = r.chunk[n:]
	r.consumed += uint64(n)
	return n, nil
}

func (h *SQLiteNamespaceHistory) inspectChunks(size uint64, expected [32]byte) (err error) {
	rows, err := h.store.querier.QueryContext(context.Background(), "SELECT ordinal,CASE WHEN length(data)<=65536 THEN data ELSE NULL END FROM chunks ORDER BY ordinal", nil)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	reader := sqliteChunkReader{rows: rows, size: size}
	digest := sha256.New()
	facts, err := protocolv4.InspectNamespaceContinuityRecord(io.TeeReader(&reader, digest), size, h.config.Scope.Limits)
	if err != nil {
		return ErrStorageFormat
	}
	if facts.StorageSchemaRevision != 0 && (facts.Tenant != h.config.Scope.Tenant || facts.Authority != h.config.Scope.Authority || facts.CapacityDigest != h.config.Scope.Capacity) {
		return ErrStorageFormat
	}
	var actual [32]byte
	digest.Sum(actual[:0])
	if actual != expected || reader.consumed != size || rows.Next(reader.values[:]) != io.EOF {
		return ErrStorageFormat
	}
	return nil
}
