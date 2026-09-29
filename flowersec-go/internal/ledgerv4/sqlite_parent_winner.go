package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// SQLitePoolAdmissionAuthority binds every candidate of a parent to one shared
// winner store. The trusted host must map direct and relay acceptors to this
// same authority, independently of their local AdmissionLedger identities.
// These methods are immutable, bounded local configuration, without I/O.
type SQLitePoolAdmissionAuthority interface {
	SQLiteAdmissionAuthority
	ParentWinnerStore() *SQLiteStore
	CheckParentWinner(SQLiteIdentity, protocolv4.AdmissionFacts) error
}

// Winner history has no release, overwrite or ordinary deletion operation.
// Exhaustion refuses new parents; restart requires independent continuity.
const sqliteParentWinnerSQL = `CREATE TABLE parent_winner (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID`

func (r *admissionRecord) encodeParentWinner(dst []byte) (int, error) {
	f := r.fields
	if f.Source != "preauthorized_pool" || f.CandidateSet == ([32]byte{}) || f.WinnerAuthority == "" {
		return 0, ErrConfiguration
	}
	return encodeParentSelection(dst, f)
}

// Both direct admission and relay claim use this exact immutable projection.
// The activation proof is available before HOP_AUTH. The e2e admission binding
// is retained by AdmissionLedger and cannot be required by a pre-FSB relay.
// Independent authority resolution validates the service behind this route;
// a local AdmissionLedger instance name is not the common service identity.
func encodeParentSelection(dst []byte, f protocolv4.AdmissionFields) (int, error) {
	w := admissionWriter{dst: dst}
	w.text("flowersec/parent-winner/3")
	for _, value := range []string{f.Source, f.Tenant, f.WinnerAuthority, f.Audience} {
		w.text(value)
	}
	for _, value := range [][]byte{f.Issuer[:], f.Lease[:], f.Artifact[:], f.Proof[:], f.CandidateSet[:], f.Candidate[:], f.Route[:], f.Attempt[:], f.ClientIdentity[:], f.ServerIdentity[:]} {
		w.bytes(value)
	}
	// Retain the original parent authorization bounds as part of the fixed
	// selection; a re-signing cannot extend an existing parent.
	for _, value := range []uint64{f.IssuedAt, f.ActivationEnd, f.SessionEnd} {
		w.uint(value)
	}
	return w.n, w.err
}

func (s *sqliteStore) readParentWinner(key, dst []byte) (n int, found bool, err error) {
	return s.readParentWinnerContext(context.Background(), key, dst)
}

func (s *sqliteStore) readParentWinnerContext(ctx context.Context, key, dst []byte) (n int, found bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.querier.QueryContext(ctx, "SELECT length(projection),CASE WHEN length(projection)<=?2 THEN projection ELSE NULL END FROM parent_winner WHERE lease=?1", []driver.NamedValue{named(1, key), named(2, int64(len(dst)))})
	if err != nil {
		return 0, false, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [2]driver.Value
	if err = rows.Next(values[:]); err == io.EOF {
		return 0, false, nil
	} else if err != nil {
		return 0, false, err
	}
	length, lok := values[0].(int64)
	projection, pok := values[1].([]byte)
	if !lok || !pok || length < 1 || length != int64(len(projection)) || length > int64(len(dst)) || length > int64(s.backing.limits.MaxRecordBytes) {
		return 0, false, ErrStorageFormat
	}
	n = copy(dst, projection)
	if err = rows.Next(values[:]); err != io.EOF {
		return 0, false, ErrStorageFormat
	}
	return n, true, nil
}

// matchParentWinner only fixes or matches a fact. It never grants a live handle,
// dispatch right or admission receipt, including after an identical replay.
// An ambiguous commit is returned as unknown and ends the original attempt.
func (s *sqliteStore) matchParentWinner(ctx context.Context, key, projection, scratch []byte, guard func() error) error {
	if len(projection) == 0 || len(projection) > len(scratch) || len(projection) > int(s.backing.limits.MaxRecordBytes) || guard == nil {
		return ErrConfiguration
	}
	if err := s.begin(ctx); err != nil {
		return err
	}
	defer s.end()
	return s.writeTransaction(ctx, guard, func() error {
		return s.matchParentWinnerInTransaction(ctx, key, projection, scratch)
	})
}

// The relay calls this while holding the same original root/leg transaction.
func (s *sqliteStore) matchParentWinnerInTransaction(ctx context.Context, key, projection, scratch []byte) error {
	n, found, err := s.readParentWinnerContext(ctx, key, scratch)
	if err != nil {
		return err
	}
	if found {
		if !bytes.Equal(scratch[:n], projection) {
			return ErrConflict
		}
		return nil
	}
	value, err := s.scalar("SELECT admission_rows+spend_rows+winner_rows+issuance_rows+relay_rows FROM manifest WHERE id=1")
	if err != nil {
		return err
	}
	count, ok := value.(int64)
	if !ok || count < 0 {
		return ErrStorageFormat
	}
	if count >= int64(s.backing.limits.MaxRecords) {
		return ErrCapacity
	}
	if err = s.exec("INSERT INTO parent_winner VALUES (?1,?2)", named(1, key), named(2, projection)); err != nil {
		return err
	}
	return s.exec("UPDATE manifest SET winner_rows=winner_rows+1 WHERE id=1")
}
