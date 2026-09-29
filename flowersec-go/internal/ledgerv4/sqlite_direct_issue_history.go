package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type DirectIssueObligationState uint8

const (
	DirectIssueReserved DirectIssueObligationState = iota
	DirectIssueCommitted
	DirectIssueRetired
)

// SQLiteDirectIssuePublication describes one exact durable row observation.
// The caller-owned output contains the immutable authority configuration,
// original obligation projection, then any original retirement proof, in that
// order. These are local storage projections, not signed wire messages. A
// publisher must own its consistent complete-State transaction independently;
// iterating these rows alone does not authenticate or publish a State/Head.
type SQLiteDirectIssuePublication struct {
	Found                                                bool
	RequestID, ArtifactDigest                            [32]byte
	LeaseID                                              [16]byte
	State                                                DirectIssueObligationState
	ConfigurationBytes, ProjectionBytes, RetirementBytes int
}

type directIssueRecord struct {
	facts                                   protocolv4.DirectIssueFacts
	request                                 [32]byte
	invocation                              [16]byte
	digest                                  [32]byte
	fence, version                          uint64
	state                                   DirectIssueObligationState
	key                                     [admissionKeyBytes]byte
	keySize, projectionSize, retirementSize int
	retirement                              [88]byte
}

func (a *SQLiteDirectIssueAuthority) enterMaintenance(ctx context.Context) error {
	if a == nil || ctx == nil {
		return ErrConfiguration
	}
	if !a.mu.TryLock() {
		return ErrCapacity
	}
	defer a.mu.Unlock()
	if a.closed {
		return ErrOwner
	}
	if a.running || a.active != nil {
		return ErrCapacity
	}
	a.running = true
	return nil
}

func (a *SQLiteDirectIssueAuthority) finishMaintenance() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	if a.closed {
		a.cleanupLocked()
	}
}

func (a *SQLiteDirectIssueAuthority) readIssue(query string, argument [32]byte, dst []byte) (record directIssueRecord, err error) {
	err = a.store.readOne(query, 9, func(v []driver.Value) error {
		key, kok := v[0].([]byte)
		request, rok := v[1].([]byte)
		invocation, iok := v[2].([]byte)
		fence, fe := readSQLiteUint(v[3])
		state, sok := v[4].(int64)
		version, ve := readSQLiteUint(v[5])
		digest, dok := v[6].([]byte)
		projection, pok := v[7].([]byte)
		retirement, xok := v[8].([]byte)
		if !kok || len(key) < 34 || len(key) > len(record.key) || !rok || len(request) != 32 || !iok || len(invocation) != 16 || fe != nil || fence == 0 || fence > a.fence || !sok || state < 0 || state > 2 || ve != nil || !dok || len(digest) != 32 || !pok || len(projection) == 0 || len(projection) > 4096 || len(projection) > len(dst) || !xok || (state == 2 && len(retirement) != 88) || (state != 2 && len(retirement) != 0) {
			return ErrStorageFormat
		}
		if (state == 0 && (version != 1 || !bytes.Equal(digest, make([]byte, 32)))) || (state == 1 && (version != 2 || bytes.Equal(digest, make([]byte, 32)))) || (state == 2 && version != 2 && version != 3) {
			return ErrStorageFormat
		}
		record.keySize = copy(record.key[:], key)
		copy(record.request[:], request)
		copy(record.invocation[:], invocation)
		copy(record.digest[:], digest)
		record.retirementSize = copy(record.retirement[:], retirement)
		record.state = DirectIssueObligationState(state)
		record.version = version
		record.fence = fence
		record.projectionSize = copy(dst, projection)
		if record.request == ([32]byte{}) || record.invocation == ([16]byte{}) {
			return ErrStorageFormat
		}
		return nil
	}, named(1, argument[:]))
	if err != nil {
		return record, err
	}
	r := topUpReader{data: dst[:record.projectionSize]}
	if r.text() != "flowersec/direct-issue/1" {
		return record, ErrStorageFormat
	}
	if r.uint() != a.store.identity.Generation || r.uint() != record.fence {
		return record, ErrFenced
	}
	f := &record.facts
	f.Scope.Schema = "Artifact"
	for _, target := range []*uint64{&f.Scope.Generation, &f.Scope.Cohort, &f.Scope.IssuedMS, &f.InitiationNotAfterMS, &f.Scope.ExpiresMS, &f.RevocationPolicyRevision} {
		*target = r.uint()
	}
	if r.text() != a.store.identity.Authority {
		return record, ErrFenced
	}
	for _, target := range []*string{&f.Scope.Tenant, &f.Scope.Authority, &f.Scope.Audience, &f.Scope.Profile, &f.RevocationPolicyID} {
		*target = r.text()
	}
	if !bytes.Equal(r.take(32), a.store.identity.StoreID[:]) || !bytes.Equal(r.take(32), record.request[:]) || !bytes.Equal(r.take(16), record.invocation[:]) {
		return record, ErrStorageFormat
	}
	for _, target := range [][]byte{f.Scope.CapacityDigest[:], f.Scope.Issuer[:], f.LeaseID[:], f.ClientIdentity[:], f.ServerIdentity[:]} {
		copy(target, r.take(len(target)))
	}
	segmentSize := r.uint()
	if segmentSize == 0 || segmentSize > 41 {
		return record, ErrStorageFormat
	}
	r.take(int(segmentSize))
	if err = r.done(); err != nil {
		return record, err
	}
	f.Namespaces, f.NamespaceCount = a.policy.NamespaceClosure()
	if err = a.policy.CheckHistoricalFacts(*f); err != nil {
		return record, err
	}
	if record.state == DirectIssueRetired {
		if (record.digest == ([32]byte{}) && record.version != 2) || (record.digest != ([32]byte{}) && record.version != 3) || bytes.Equal(record.retirement[:32], make([]byte, 32)) || bytes.Equal(record.retirement[32:64], make([]byte, 32)) || binary.BigEndian.Uint64(record.retirement[64:72]) <= f.Scope.Cohort || binary.BigEndian.Uint64(record.retirement[72:80]) > binary.BigEndian.Uint64(record.retirement[80:88]) {
			return record, ErrStorageFormat
		}
	}
	var expected [admissionKeyBytes]byte
	n, err := (&admissionRecord{fields: protocolv4.AdmissionFields{Tenant: f.Scope.Tenant, Issuer: f.Scope.Issuer, Lease: f.LeaseID}}).key(expected[:])
	if err != nil || !bytes.Equal(expected[:n], record.key[:record.keySize]) {
		return record, ErrStorageFormat
	}
	return record, nil
}

const readDirectIssueColumns = "SELECT lease,request,invocation,fence,state,version,artifact,projection,retirement FROM issuance "

// ReadNextObligation visits one request key, including retained tombstones.
// It never performs an unbounded skip over retired records. An all-zero cursor
// starts enumeration; subsequent calls use the returned original RequestID.
// The caller pre-admits at least 16384 output bytes and owns their cleanup.
func (a *SQLiteDirectIssueAuthority) ReadNextObligation(ctx context.Context, after [32]byte, dst []byte) (publication SQLiteDirectIssuePublication, err error) {
	if len(dst) < 16384 {
		return publication, ErrConfiguration
	}
	if err = a.enterMaintenance(ctx); err != nil {
		return publication, err
	}
	defer a.finishMaintenance()
	window, err := timev4.NewWindow(a.config.Policy.Clock, a.config.WorkMS)
	if err != nil {
		return publication, err
	}
	if err = a.checkBase(ctx); err != nil {
		return publication, err
	}
	s := a.store
	if err = s.begin(ctx); err != nil {
		return publication, err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return publication, err
	}
	var row [4096]byte
	record, err := a.readIssue(readDirectIssueColumns+"WHERE request>?1 ORDER BY request LIMIT 1", after, row[:])
	if errors.Is(err, io.EOF) {
		return publication, nil
	}
	if err != nil {
		return publication, err
	}
	if err = window.Check(); err != nil {
		return publication, err
	}
	if err = a.checkBase(ctx); err != nil {
		return publication, err
	}
	n := copy(dst, a.configuration[:a.configurationSize])
	n += copy(dst[n:], row[:record.projectionSize])
	n += copy(dst[n:], record.retirement[:record.retirementSize])
	if err = window.Check(); err == nil {
		err = a.checkBase(ctx)
	}
	if err != nil {
		clear(dst[:n])
		return publication, err
	}
	return SQLiteDirectIssuePublication{Found: true, RequestID: record.request, ArtifactDigest: record.digest, LeaseID: record.facts.LeaseID, State: record.state, ConfigurationBytes: a.configurationSize, ProjectionBytes: record.projectionSize, RetirementBytes: record.retirementSize}, nil
}

func directIssueRetirementBytes(proof protocolv4.DirectIssueRetirementEvidence) (out [88]byte) {
	copy(out[:32], proof.Head[:])
	copy(out[32:64], proof.State[:])
	binary.BigEndian.PutUint64(out[64:72], proof.ConnectionFloor)
	binary.BigEndian.PutUint64(out[72:80], proof.LowerMS)
	binary.BigEndian.PutUint64(out[80:88], proof.UpperMS)
	return
}

// RetireMature releases only the State/outstanding share after an authenticated
// complete-State frontier and maximum-impact maturity proof. The full original
// facts, digest, request uniqueness and proof remain as a bounded tombstone.
// MaxRecords still counts every row; a full history refuses fresh issuance.
// False with nil error means the original responsibility is not yet mature.
func (a *SQLiteDirectIssueAuthority) RetireMature(ctx context.Context, request [32]byte) (retired bool, err error) {
	if request == ([32]byte{}) {
		return false, ErrConfiguration
	}
	if err = a.enterMaintenance(ctx); err != nil {
		return false, err
	}
	defer a.finishMaintenance()
	window, err := timev4.NewWindow(a.config.Policy.Clock, a.config.WorkMS)
	if err != nil {
		return false, err
	}
	if err = a.checkBase(ctx); err != nil {
		return false, err
	}
	s := a.store
	if err = s.begin(ctx); err != nil {
		return false, err
	}
	defer s.end()
	if err = s.checkFence(); err != nil {
		return false, err
	}
	var row [4096]byte
	record, err := a.readIssue(readDirectIssueColumns+"WHERE request=?1", request, row[:])
	if err != nil {
		return false, err
	}
	if record.state == DirectIssueRetired {
		return true, nil
	}
	proof, ready, err := a.policy.ProveRetirement(record.facts)
	if err != nil || !ready {
		return false, err
	}
	encoded := directIssueRetirementBytes(proof)
	guard := func() error {
		if err := window.Check(); err != nil {
			return err
		}
		if err := a.checkBase(ctx); err != nil {
			return err
		}
		current, ready, err := a.policy.ProveRetirement(record.facts)
		if err != nil {
			return err
		}
		if !ready || current.Head != proof.Head || current.State != proof.State || current.ConnectionFloor < proof.ConnectionFloor || current.LowerMS < proof.LowerMS {
			return ErrConflict
		}
		return nil
	}
	err = s.writeTransaction(ctx, guard, func() error {
		if err := s.exec("UPDATE issuance SET state=2,version=?1,retirement=?2 WHERE request=?3 AND lease=?4 AND invocation=?5 AND fence=?6 AND state=?7 AND version=?8 AND artifact=?9 AND projection=?10 AND length(retirement)=0", named(1, sqliteUint(record.version+1)), named(2, encoded[:]), named(3, record.request[:]), named(4, record.key[:record.keySize]), named(5, record.invocation[:]), named(6, sqliteUint(record.fence)), named(7, int64(record.state)), named(8, sqliteUint(record.version)), named(9, record.digest[:]), named(10, row[:record.projectionSize])); err != nil {
			return err
		}
		if err := s.changedOne(); err != nil {
			return err
		}
		if err := s.exec("UPDATE direct_issue_config SET rows=rows-1,state_bytes=state_bytes-?1 WHERE id=1 AND rows>0 AND state_bytes>=?2", named(1, int64(directIssuePerLeaseStateBytes)), named(2, int64(directIssueFixedStateBytes+directIssuePerLeaseStateBytes))); err != nil {
			return err
		}
		return s.changedOne()
	})
	if err != nil {
		return false, err
	}
	return true, nil
}
