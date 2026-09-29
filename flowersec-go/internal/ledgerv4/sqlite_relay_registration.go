package ledgerv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

const sqliteRelayRegistrationSQL = `CREATE TABLE relay_issuance (selection BLOB PRIMARY KEY CHECK(length(selection) BETWEEN 66 AND 193), sources BLOB NOT NULL CHECK(length(sources) BETWEEN 84 AND 338), state INTEGER NOT NULL CHECK(state IN (0,1)), invocation BLOB NOT NULL CHECK(length(invocation)=16), digest BLOB NOT NULL CHECK(length(digest)=32), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 65536), CHECK(state=1 OR (invocation<>zeroblob(16) AND digest=zeroblob(32) AND length(projection)=65536))) STRICT, WITHOUT ROWID`

// Implementations are private original publication owners. No public receipt
// or restored registration can implement this commit gate.
type sqliteRelayPublication interface {
	checkCommit() error
	invocationID() [16]byte
	hasReservation(protocolv4.RelayParentKey) bool
}

// Reserve the actual worst-case record pages before the source may claim TxA.
// A failed/unknown reservation remains a non-authorizing row. It cannot be
// filled after restart because only this original invocation owns the permit.
func (s *sqliteStore) reserveRelayRegistration(ctx context.Context, selection protocolv4.RelayParentKey, identities [2]SQLiteIdentity, invocation [16]byte, check func() error) error {
	_, err := s.reservePoolRelayRegistration(ctx, selection, identities, invocation, nil, nil, check)
	return err
}

func (s *sqliteStore) reservePoolRelayRegistration(ctx context.Context, selection protocolv4.RelayParentKey, identities [2]SQLiteIdentity, invocation [16]byte, original, scratch []byte, check func() error) (bool, error) {
	var keyBacking [193]byte
	var sourceBacking [338]byte
	key, err := relayRegistrationKey(keyBacking[:], selection)
	if err != nil {
		return false, err
	}
	sources, err := relayRegistrationSources(sourceBacking[:], identities)
	if err != nil {
		return false, err
	}
	if err = s.begin(ctx); err != nil {
		return false, err
	}
	defer s.end()
	if s.backing.limits.MaxRecordBytes < protocolv4.RelayParentRecordMaxBytes {
		return false, ErrConfiguration
	}
	if err = s.checkFence(); err != nil {
		return false, err
	}
	if original != nil {
		n, err := s.readRelayRegistration(key, sources, scratch)
		if err == nil {
			if !bytes.Equal(original, scratch[:n]) {
				return false, ErrConflict
			}
			if err = ctx.Err(); err == nil {
				err = check()
			}
			return false, err
		}
		if !errors.Is(err, ErrRelayHistoryUnknown) {
			return false, err
		}
	}
	err = s.writeTransaction(ctx, check, func() error {
		err := s.readOne("SELECT 1 FROM relay_issuance WHERE selection=?1", 1, func([]driver.Value) error { return ErrConflict }, named(1, key))
		if !errors.Is(err, io.EOF) {
			return err
		}
		total, err := s.scalar("SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows FROM manifest WHERE id=1")
		if err != nil {
			return err
		}
		count, ok := total.(int64)
		if !ok || count < 0 {
			return ErrStorageFormat
		}
		if uint64(count) >= uint64(s.backing.limits.MaxRecords) {
			return ErrCapacity
		}
		if err = s.exec("INSERT INTO relay_issuance VALUES(?1,?2,0,?3,zeroblob(32),zeroblob(65536))", named(1, key), named(2, sources), named(3, invocation[:])); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET relay_rows=relay_rows+1 WHERE id=1")
	})
	return true, err
}

func (s *sqliteStore) matchReservedRelayRegistration(key, sources []byte, invocation [16]byte) error {
	err := s.readOne("SELECT state=0,sources=?2,invocation=?3,length(projection)=65536,digest=zeroblob(32) FROM relay_issuance WHERE selection=?1", 5, func(v []driver.Value) error {
		for _, value := range v {
			if value != int64(1) {
				return ErrConflict
			}
		}
		return nil
	}, named(1, key), named(2, sources), named(3, invocation[:]))
	if errors.Is(err, io.EOF) {
		return ErrRelayHistoryUnknown
	}
	return err
}

// releaseRelayReservation removes only unused physical capacity after the
// owning publication has irrevocably closed and its actual work has returned.
// It never deletes ready issuance or any spend, winner or relay-claim history.
// Unknown cleanup retains a non-authorizing reservation; it grants no retry.
func (s *sqliteStore) releaseRelayReservation(ctx context.Context, selection protocolv4.RelayParentKey, identities [2]SQLiteIdentity, invocation [16]byte) error {
	var keyBacking [193]byte
	var sourceBacking [338]byte
	key, err := relayRegistrationKey(keyBacking[:], selection)
	if err != nil {
		return err
	}
	sources, err := relayRegistrationSources(sourceBacking[:], identities)
	if err != nil {
		return err
	}
	if err = s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	return s.writeTransaction(ctx, s.checkFence, func() error {
		if err := s.exec("DELETE FROM relay_issuance WHERE selection=?1 AND sources=?2 AND invocation=?3 AND state=0", named(1, key), named(2, sources), named(3, invocation[:])); err != nil {
			return err
		}
		value, err := s.scalar("SELECT changes()")
		if err != nil {
			return err
		}
		count, ok := value.(int64)
		if !ok || count < 0 || count > 1 {
			return ErrStorageFormat
		}
		if count == 0 {
			return nil
		}
		if err := s.exec("UPDATE manifest SET relay_rows=relay_rows-1 WHERE id=1 AND relay_rows>0"); err != nil {
			return err
		}
		return s.changedOne()
	})
}

func relayRegistrationKey(dst []byte, key protocolv4.RelayParentKey) ([]byte, error) {
	if len(dst) < 193 || len(key.Tenant) == 0 || len(key.Tenant) > 128 || key.Issuer == ([16]byte{}) || key.Lease == ([16]byte{}) || key.Candidate == ([16]byte{}) || key.Attempt == ([16]byte{}) {
		return nil, ErrConfiguration
	}
	dst[0] = byte(len(key.Tenant))
	n := 1 + copy(dst[1:], key.Tenant)
	for _, id := range [][16]byte{key.Issuer, key.Lease, key.Candidate, key.Attempt} {
		n += copy(dst[n:], id[:])
	}
	return dst[:n:n], nil
}

func relayRegistrationSources(dst []byte, sources [2]SQLiteIdentity) ([]byte, error) {
	if len(dst) < 338 {
		return nil, ErrConfiguration
	}
	n := 0
	for _, identity := range sources {
		if !validSQLiteIdentity(identity) {
			return nil, ErrConfiguration
		}
		dst[n] = byte(len(identity.Authority))
		n++
		n += copy(dst[n:], identity.Authority)
		n += copy(dst[n:], identity.StoreID[:])
		binary.BigEndian.PutUint64(dst[n:], identity.Generation)
		n += 8
	}
	return dst[:n:n], nil
}

func relayRegistrationDigest(key, sources, projection []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("flowersec/v4/sqlite-relay-issuance\x00"))
	for _, value := range [][]byte{key, sources, projection} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(value)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// readRelayRegistration copies one bounded public row. A caller supplies both
// original issuance identities from independent deployment configuration.
// There is no lookup by peer URL and no inference from a relay claim record.
func (s *sqliteStore) readRelayRegistration(key, sources, dst []byte) (int, error) {
	n := 0
	err := s.readOne("SELECT CASE WHEN length(sources)<=338 THEN sources ELSE NULL END,CASE WHEN length(digest)=32 THEN digest ELSE NULL END,length(projection),CASE WHEN length(projection)<=?2 THEN projection ELSE NULL END FROM relay_issuance WHERE selection=?1 AND state=1", 4, func(v []driver.Value) error {
		storedSources, ok := v[0].([]byte)
		digest, dok := v[1].([]byte)
		length, lok := v[2].(int64)
		wire, wok := v[3].([]byte)
		if !ok || !dok || !lok || !wok || length <= 0 || length != int64(len(wire)) || length > int64(len(dst)) || length > int64(s.backing.limits.MaxRecordBytes) || len(digest) != 32 {
			return ErrStorageFormat
		}
		if !bytes.Equal(storedSources, sources) {
			return ErrOwner
		}
		want := relayRegistrationDigest(key, sources, wire)
		if !bytes.Equal(digest, want[:]) {
			return ErrStorageFormat
		}
		n = copy(dst, wire)
		return nil
	}, named(1, key), named(2, int64(min(len(dst), protocolv4.RelayParentRecordMaxBytes))))
	if errors.Is(err, io.EOF) {
		return 0, ErrRelayHistoryUnknown
	}
	return n, err
}

func (s *sqliteStore) restoreRelayRegistration(ctx context.Context, input SQLiteRelayParentRegistration, dst []byte, environment resourcev4.Reference) (*protocolv4.RelayParentProjection, error) {
	var keyBacking [193]byte
	var sourceBacking [338]byte
	key, err := relayRegistrationKey(keyBacking[:], *input.RestoreKey)
	if err != nil {
		return nil, err
	}
	sources, err := relayRegistrationSources(sourceBacking[:], input.IssuanceIdentity)
	if err != nil {
		return nil, err
	}
	if err = s.begin(ctx); err != nil {
		return nil, err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return nil, err
	}
	n, err := s.readRelayRegistration(key, sources, dst)
	if err != nil {
		return nil, err
	}
	p, err := protocolv4.RestoreRelayParentProjection(dst[:n:n], input.Mapping, input.Parent, environment)
	if err != nil {
		return nil, err
	}
	actual, err := p.Key()
	if err != nil || actual != *input.RestoreKey {
		return nil, ErrStorageFormat
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = environment.Check(); err != nil {
		return nil, err
	}
	if err = s.checkFence(); err != nil {
		return nil, err
	}
	return p, nil
}

// persistRelayRegistration is reachable only after BOTH committed leg receipts
// have been matched. Duplicate registration preserves exact original bytes;
// conflicts never overwrite history. Capacity includes this durable row even
// after the issuer's original secret-bearing outbox is retired. There is no
// expiry-based deletion or operation capable of reopening a consumed leg.
func (s *sqliteStore) persistRelayRegistration(ctx context.Context, input SQLiteRelayParentRegistration, p *protocolv4.RelayParentProjection, dst, original []byte, environment resourcev4.Reference, publication sqliteRelayPublication) error {
	selection, err := p.Key()
	if err != nil {
		return err
	}
	var keyBacking [193]byte
	var sourceBacking [338]byte
	key, err := relayRegistrationKey(keyBacking[:], selection)
	if err != nil {
		return err
	}
	sources, err := relayRegistrationSources(sourceBacking[:], input.IssuanceIdentity)
	if err != nil {
		return err
	}
	n, err := p.CopyPublicRecord(dst)
	if err != nil {
		return err
	}
	if uint64(n) > uint64(s.backing.limits.MaxRecordBytes) {
		return ErrCapacity
	}
	wire := dst[:n:n]
	digest := relayRegistrationDigest(key, sources, wire)
	if err = s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return err
	}
	check := func() error {
		if publication != nil {
			if err := publication.checkCommit(); err != nil {
				return err
			}
		}
		if err := environment.Check(); err != nil {
			return err
		}
		for side, receipt := range input.Committed {
			if err := receipt.matchProjection(input.IssuanceIdentity[side], protocolv4.Direction(side), environment, p); err != nil {
				return err
			}
		}
		return p.CheckCurrent(input.Parent, environment)
	}
	if err = check(); err != nil {
		return err
	}
	if publication != nil && !publication.hasReservation(selection) {
		// A retained pool registration already has its own complete original
		// bytes. Confirm it without a write transaction on a replay.
		n, err := s.readRelayRegistration(key, sources, original)
		if err != nil {
			return err
		}
		if !bytes.Equal(original[:n], wire) {
			return ErrConflict
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		return check()
	}
	return s.writeTransaction(ctx, check, func() error {
		if publication != nil && publication.hasReservation(selection) {
			if err := s.matchReservedRelayRegistration(key, sources, publication.invocationID()); err != nil {
				return err
			}
			return s.exec("UPDATE relay_issuance SET state=1,digest=?2,projection=?3 WHERE selection=?1", named(1, key), named(2, digest[:]), named(3, wire))
		}
		n, err := s.readRelayRegistration(key, sources, original)
		if err == nil {
			if !bytes.Equal(original[:n], wire) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, ErrRelayHistoryUnknown) {
			return err
		}
		if publication != nil {
			return ErrRelayHistoryUnknown
		}
		// Reserved rows are deliberately not readable as original issuance.
		// An ordinary installer must not overwrite or adopt another invocation.
		err = s.readOne("SELECT 1 FROM relay_issuance WHERE selection=?1", 1, func([]driver.Value) error { return ErrConflict }, named(1, key))
		if !errors.Is(err, io.EOF) {
			return err
		}
		total, err := s.scalar("SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows FROM manifest WHERE id=1")
		if err != nil {
			return err
		}
		count, ok := total.(int64)
		if !ok || count < 0 {
			return ErrStorageFormat
		}
		if uint64(count) >= uint64(s.backing.limits.MaxRecords) {
			return ErrCapacity
		}
		if err = s.exec("INSERT INTO relay_issuance VALUES(?1,?2,1,zeroblob(16),?3,?4)", named(1, key), named(2, sources), named(3, digest[:]), named(4, wire)); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET relay_rows=relay_rows+1 WHERE id=1")
	})
}
