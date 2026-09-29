package ledgerv4

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// TopUpPoolRead is detached storage metadata. The returned bytes alone never
// grant Connect/Acquire: the source must restore the exact original key owner,
// verify credentials and construct a complete ConnectionMaterial before taking.
type TopUpPoolRead struct {
	Entry                                              protocolv4.TopUpEntryFacts
	CertificateBytes, KeyReferenceBytes, MaterialBytes int
	Found                                              bool
}

// CheckBinding fixes the source namespace, owner and storage bounds before a
// source worker is constructed. It performs no database or provider I/O.
func (j *SQLiteTopUpJournal) CheckBinding(tenant string, source [16]byte, generation uint64, items uint32, environment resourcev4.Reference) error {
	if j == nil || j.store == nil || j.store.sqliteStore == nil {
		return ErrConfiguration
	}
	j.store.mu.Lock()
	defer j.store.mu.Unlock()
	if j.store.closed || j.store.complete || j.config.Tenant != tenant || j.config.Source != source || j.config.BindingGeneration != generation || items == 0 || items > j.store.backing.limits.MaxRecords-1 {
		return ErrConfiguration
	}
	return j.store.reservation.CheckSameEnvironment(environment)
}

// ReadPoolNext copies at most one installed item into preadmitted caller
// buffers. It neither removes the item nor authorizes it. The original source
// serializes restoration and reads in sequence order with a fixed item ceiling.
func (j *SQLiteTopUpJournal) ReadPoolNext(ctx context.Context, after uint64, certificate, keyReference, material []byte) (out TopUpPoolRead, err error) {
	if len(certificate) < int(j.config.IdentityBytes) || len(keyReference) < int(j.config.KeyReferenceBytes) || len(material) < 65536 {
		return out, ErrCapacity
	}
	if err = j.store.begin(ctx); err != nil {
		return out, err
	}
	defer j.store.end()
	defer func() {
		if err != nil {
			clear(certificate)
			clear(keyReference)
			clear(material)
			out = TopUpPoolRead{}
		}
	}()
	if err = j.store.checkFence(); err != nil {
		return out, err
	}
	if err = j.check(); err != nil {
		return out, err
	}
	state, err := j.readRecovery()
	if err != nil {
		return out, err
	}
	if state.PermanentFenceGeneration != 0 || state.State == TopUpJournalTerminal && state.Terminal.Permanent {
		return out, ErrFenced
	}
	err = j.store.readOne("SELECT CASE WHEN length(sequence)=8 THEN sequence ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(expiry)=8 THEN expiry ELSE NULL END,CASE WHEN length(material_digest)=32 THEN material_digest ELSE NULL END,CASE WHEN length(identity_digest)=32 THEN identity_digest ELSE NULL END,CASE WHEN length(record)<=?2 THEN record ELSE NULL END FROM pool WHERE sequence>?1 ORDER BY sequence LIMIT 1", 6, func(v []driver.Value) error {
		var e error
		for i, dst := range []*uint64{&out.Entry.Sequence, &out.Entry.Generation, &out.Entry.ExpiryMS} {
			*dst, e = readSQLiteUint(v[i])
			if e != nil {
				return e
			}
		}
		digest, dok := v[3].([]byte)
		identity, iok := v[4].([]byte)
		record, rok := v[5].([]byte)
		if !dok || len(digest) != 32 || !iok || len(identity) != 32 || !rok || out.Entry.Sequence <= after || out.Entry.Sequence > state.ArtifactFrontier || out.Entry.Generation == 0 || out.Entry.Generation > state.BindingGeneration || out.Entry.ExpiryMS == 0 {
			return ErrStorageFormat
		}
		copy(out.Entry.Material[:], digest)
		copy(out.Entry.Identity[:], identity)
		reader := topUpReader{data: record}
		certLen := reader.uint()
		if certLen == 0 || certLen > uint64(j.config.IdentityBytes) {
			return ErrStorageFormat
		}
		cert := reader.take(int(certLen))
		keyLen := reader.uint()
		if keyLen == 0 || keyLen > uint64(j.config.KeyReferenceBytes) {
			return ErrStorageFormat
		}
		key := reader.take(int(keyLen))
		materialLen := reader.uint()
		if materialLen == 0 || materialLen > 65536 {
			return ErrStorageFormat
		}
		value := reader.take(int(materialLen))
		if e = reader.done(); e != nil {
			return e
		}
		certDigest, e := protocolv4.TopUpIdentityDigest(cert)
		if e != nil || certDigest != out.Entry.Identity || sha256.Sum256(value) != out.Entry.Material {
			return ErrStorageFormat
		}
		out.CertificateBytes = copy(certificate, cert)
		out.KeyReferenceBytes = copy(keyReference, key)
		out.MaterialBytes = copy(material, value)
		out.Found = true
		return nil
	}, named(1, sqliteUint(after)), named(2, int64(j.store.backing.limits.MaxRecordBytes)))
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err == nil {
		err = j.check()
	}
	if err == nil {
		err = ctx.Err()
	}
	return out, err
}

// TakePool removes one exact installed tuple durably before the source hands
// its already-validated immutable ConnectionMaterial to Acquire. It never
// changes Applied, artifact_frontier, TopUp retirement or once/spend ledgers.
// ErrUnknown cannot authorize handoff; the caller must retain/discard its local
// owner until actual cleanup, and cannot infer delivery from a later missing row.
func (j *SQLiteTopUpJournal) TakePool(ctx context.Context, expected protocolv4.TopUpEntryFacts) error {
	if expected.Sequence == 0 || expected.Generation == 0 {
		return ErrConfiguration
	}
	if err := j.store.begin(ctx); err != nil {
		return err
	}
	defer j.store.end()
	guard := func() error {
		if err := j.check(); err != nil {
			return err
		}
		now, err := j.config.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(expected.ExpiryMS) {
			return topUpFailure(protocolv4.V4TopUpErrorCodeSourceContractInvalid)
		}
		return nil
	}
	return j.store.writeTransaction(ctx, guard, func() error {
		state, err := j.readRecovery()
		if err != nil {
			return err
		}
		if state.PermanentFenceGeneration != 0 || state.State == TopUpJournalTerminal && state.Terminal.Permanent {
			return ErrFenced
		}
		if state.BindingGeneration != j.config.BindingGeneration || expected.Sequence > state.ArtifactFrontier {
			return ErrConflict
		}
		var size int64
		err = j.store.readOne("SELECT CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(expiry)=8 THEN expiry ELSE NULL END,CASE WHEN length(material_digest)=32 THEN material_digest ELSE NULL END,CASE WHEN length(identity_digest)=32 THEN identity_digest ELSE NULL END,length(record) FROM pool WHERE sequence=?1", 5, func(v []driver.Value) error {
			generation, e := readSQLiteUint(v[0])
			if e != nil {
				return e
			}
			expiry, e := readSQLiteUint(v[1])
			if e != nil {
				return e
			}
			digest, dok := v[2].([]byte)
			identity, iok := v[3].([]byte)
			var sok bool
			size, sok = v[4].(int64)
			if !dok || len(digest) != 32 || !iok || len(identity) != 32 || !sok || size < 1 || size > int64(j.store.backing.limits.MaxRecordBytes) {
				return ErrStorageFormat
			}
			if generation != expected.Generation || expiry != expected.ExpiryMS || [32]byte(digest) != expected.Material || [32]byte(identity) != expected.Identity {
				return ErrConflict
			}
			return nil
		}, named(1, sqliteUint(expected.Sequence)))
		if errors.Is(err, io.EOF) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if err = j.store.exec("DELETE FROM pool WHERE sequence=?1", named(1, sqliteUint(expected.Sequence))); err != nil {
			return err
		}
		if err = j.store.changedOne(); err != nil {
			return err
		}
		if err = j.store.exec("UPDATE manifest SET pool_count=pool_count-1,pool_bytes=pool_bytes-?1 WHERE id=1 AND pool_count>0 AND pool_bytes>=?1", named(1, size)); err != nil {
			return err
		}
		return j.store.changedOne()
	})
}

// RemoveExpiredPool is bounded authority maintenance. Only a trusted lower
// bound past an item's expiry permits reclamation. It is not an Acquire, does
// not consume a lease, and never advances a TopUp or artifact frontier.
func (j *SQLiteTopUpJournal) RemoveExpiredPool(ctx context.Context, limit uint8) (count uint8, err error) {
	if limit == 0 || limit > 8 {
		return 0, ErrConfiguration
	}
	if err = j.store.begin(ctx); err != nil {
		return 0, err
	}
	defer j.store.end()
	err = j.store.writeTransaction(ctx, j.check, func() error {
		for count < limit {
			now, e := j.config.Clock.Sample()
			if e != nil {
				return e
			}
			var sequence []byte
			var size int64
			e = j.store.readOne("SELECT CASE WHEN length(sequence)=8 THEN sequence ELSE NULL END,length(record) FROM pool WHERE expiry<=?1 ORDER BY sequence LIMIT 1", 2, func(v []driver.Value) error {
				b, ok := v[0].([]byte)
				var sok bool
				size, sok = v[1].(int64)
				if !ok || len(b) != 8 || !sok || size < 1 || size > int64(j.store.backing.limits.MaxRecordBytes) {
					return ErrStorageFormat
				}
				sequence = append([]byte(nil), b...)
				return nil
			}, named(1, sqliteUint(now.LowerMS)))
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				return e
			}
			if e = j.store.exec("DELETE FROM pool WHERE sequence=?1", named(1, sequence)); e != nil {
				return e
			}
			if e = j.store.changedOne(); e != nil {
				return e
			}
			if e = j.store.exec("UPDATE manifest SET pool_count=pool_count-1,pool_bytes=pool_bytes-?1 WHERE id=1 AND pool_count>0 AND pool_bytes>=?1", named(1, size)); e != nil {
				return e
			}
			if e = j.store.changedOne(); e != nil {
				return e
			}
			count++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// PoolDigest identifies this source's current installed membership for a new
// intent. The stable source sequence space does not depend on this digest.
// A bounded read transaction prevents a concurrent local take from mixing two
// pool snapshots. The digest contains only fixed-width facts and domain binding.
func (j *SQLiteTopUpJournal) PoolDigest(ctx context.Context) (out [32]byte, err error) {
	if err = j.store.begin(ctx); err != nil {
		return out, err
	}
	defer j.store.end()
	if err = j.store.checkFence(); err != nil {
		return out, err
	}
	if err = j.check(); err != nil {
		return out, err
	}
	if err = j.store.exec("BEGIN DEFERRED"); err != nil {
		return out, err
	}
	defer func() {
		if e := j.store.exec("ROLLBACK"); e != nil {
			err = errors.Join(err, e)
			out = [32]byte{}
		}
	}()
	state, err := j.readRecovery()
	if err != nil {
		return out, err
	}
	hash := sha256.New()
	hash.Write([]byte("flowersec/v6/topup-pool-state\x00"))
	hash.Write([]byte{byte(len(j.config.Tenant))})
	hash.Write([]byte(j.config.Tenant))
	hash.Write(j.config.Source[:])
	hash.Write(sqliteUint(state.ArtifactFrontier))
	after := uint64(0)
	for rows := uint32(0); ; rows++ {
		var sequence uint64
		err = j.store.readOne("SELECT CASE WHEN length(sequence)=8 THEN sequence ELSE NULL END,CASE WHEN length(generation)=8 THEN generation ELSE NULL END,CASE WHEN length(expiry)=8 THEN expiry ELSE NULL END,CASE WHEN length(material_digest)=32 THEN material_digest ELSE NULL END,CASE WHEN length(identity_digest)=32 THEN identity_digest ELSE NULL END FROM pool WHERE sequence>?1 ORDER BY sequence LIMIT 1", 5, func(v []driver.Value) error {
			var e error
			sequence, e = readSQLiteUint(v[0])
			if e != nil {
				return e
			}
			if sequence <= after || sequence > state.ArtifactFrontier || rows >= j.store.backing.limits.MaxRecords-1 {
				return ErrStorageFormat
			}
			for i, value := range v {
				b, ok := value.([]byte)
				want := 8
				if i >= 3 {
					want = 32
				}
				if !ok || len(b) != want {
					return ErrStorageFormat
				}
				hash.Write(b)
			}
			return nil
		}, named(1, sqliteUint(after)))
		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
		if err != nil {
			return out, err
		}
		after = sequence
		if err = ctx.Err(); err != nil {
			return out, err
		}
	}
	if err = j.check(); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	hash.Sum(out[:0])
	return out, nil
}

// CheckCurrentOwner is a local availability/fencing check, not a durable
// transaction or a proof of permission. The caller checks access separately.
func (j *SQLiteTopUpJournal) CheckCurrentOwner() error {
	if j == nil || j.store == nil || j.store.sqliteStore == nil {
		return ErrConfiguration
	}
	j.store.mu.Lock()
	closed := j.store.closed || j.store.complete
	reservation := j.store.reservation
	j.store.mu.Unlock()
	if closed {
		return ErrStorageUnavailable
	}
	if err := reservation.Check(); err != nil {
		return err
	}
	return j.check()
}
