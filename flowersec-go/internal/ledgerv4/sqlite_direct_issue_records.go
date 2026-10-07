package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func (s *sqliteStore) inspectDirectIssueConfiguration(decoder *protocolv4.StorageFactsDecoder) (policy protocolv4.StoredDirectIssuePolicy, active uint64, err error) {
	err = s.readOne("SELECT CASE WHEN length(configuration) BETWEEN 1 AND 8192 THEN configuration ELSE NULL END,rows,state_bytes,credit,last_upper FROM direct_issue_config WHERE id=1", 5, func(v []driver.Value) error {
		wire, wok := v[0].([]byte)
		rows, rok := v[1].(int64)
		stateBytes, sok := v[2].(int64)
		credit, ce := readSQLiteUint(v[3])
		_, te := readSQLiteUint(v[4])
		if !wok || !rok || rows < 0 || !sok || stateBytes < 0 || ce != nil || te != nil || s.backing.limits.MaxRecordBytes < 4096 {
			return ErrStorageFormat
		}
		r := topUpReader{data: wire}
		if storageText(&r) != "flowersec/direct-issuer/1" {
			return ErrStorageFormat
		}
		maximum, capacity, rate, burst, work, fixed, perLease := r.uint(), r.uint(), r.uint(), r.uint(), r.uint(), r.uint(), r.uint()
		if maximum == 0 || maximum > 1<<20 || maximum > uint64(s.backing.limits.MaxRecords) || capacity > 1<<32 || capacity < directIssueFixedStateBytes+maximum*directIssuePerLeaseStateBytes || rate == 0 || rate > 6000 || burst == 0 || burst > rate || work == 0 || work > 2000 || fixed != directIssueFixedStateBytes || perLease != directIssuePerLeaseStateBytes || uint64(rows) > maximum || uint64(stateBytes) != fixed+uint64(rows)*perLease || uint64(stateBytes) > capacity || credit > burst*60000 {
			return ErrStorageFormat
		}
		var parts [4][]byte
		for i := range parts {
			prefix := r.take(4)
			if len(prefix) != 4 {
				return ErrStorageFormat
			}
			n := binary.BigEndian.Uint32(prefix)
			if n == 0 || n > 2048 {
				return ErrStorageFormat
			}
			parts[i] = r.take(int(n))
		}
		closure := r.take(32)
		if r.done() != nil || storageZero(closure) {
			return ErrStorageFormat
		}
		var err error
		policy, err = decoder.InspectDirectIssuePolicy(parts)
		if err != nil {
			return ErrStorageFormat
		}
		if capacity > policy.StateBytes || maximum > policy.Leases || maximum > policy.Segments {
			return ErrStorageFormat
		}
		active = uint64(rows)
		return nil
	})
	return
}

func (s *sqliteStore) inspectDirectIssueRecord(values []driver.Value, epoch uint64, policy protocolv4.StoredDirectIssuePolicy, decoder *protocolv4.StorageFactsDecoder) (retired bool, err error) {
	key, kok := values[0].([]byte)
	request, rok := values[1].([]byte)
	invocation, iok := values[2].([]byte)
	fence, fe := readSQLiteUint(values[3])
	state, sok := values[4].(int64)
	version, ve := readSQLiteUint(values[5])
	digest, dok := values[6].([]byte)
	wire, wok := values[7].([]byte)
	retirement, tok := values[8].([]byte)
	if !kok || !rok || len(request) != 32 || storageZero(request) || !iok || len(invocation) != 16 || storageZero(invocation) || fe != nil || fence == 0 || fence > epoch || !sok || state < 0 || state > 2 || ve != nil || !dok || len(digest) != 32 || !wok || !tok || (state == 2 && len(retirement) != 88) || (state != 2 && len(retirement) != 0) {
		return false, ErrStorageFormat
	}
	if (state == 0 && (version != 1 || !storageZero(digest))) || (state == 1 && (version != 2 || storageZero(digest))) || (state == 2 && ((storageZero(digest) && version != 2) || (!storageZero(digest) && version != 3))) {
		return false, ErrStorageFormat
	}
	r := topUpReader{data: wire}
	if storageText(&r) != "flowersec/direct-issue/1" || r.uint() != s.identity.Generation || r.uint() != fence {
		return false, ErrStorageFormat
	}
	var f protocolv4.DirectIssueFacts
	f.Scope.Schema = "Artifact"
	for _, dst := range []*uint64{&f.Scope.Generation, &f.Scope.Cohort, &f.Scope.IssuedMS, &f.InitiationNotAfterMS, &f.Scope.ExpiresMS, &f.RevocationPolicyRevision} {
		*dst = r.uint()
	}
	if storageText(&r) != s.identity.Authority {
		return false, ErrStorageFormat
	}
	for _, dst := range []*string{&f.Scope.Tenant, &f.Scope.Authority, &f.Scope.Audience, &f.Scope.Profile, &f.RevocationPolicyID} {
		*dst = storageText(&r)
	}
	if !bytes.Equal(r.take(32), s.identity.StoreID[:]) || !bytes.Equal(r.take(32), request) || !bytes.Equal(r.take(16), invocation) {
		return false, ErrStorageFormat
	}
	for _, dst := range [][]byte{f.Scope.CapacityDigest[:], f.Scope.Issuer[:], f.LeaseID[:], f.ClientIdentity[:], f.ServerIdentity[:]} {
		copy(dst, r.take(len(dst)))
	}
	segment := storageSizedBytes(&r, 41)
	if r.done() != nil || !storageParentKey(key, f.Scope.Tenant, f.Scope.Issuer[:], f.LeaseID[:]) {
		return false, ErrStorageFormat
	}
	if err := decoder.CheckDirectIssue(policy, f, segment); err != nil {
		return false, ErrStorageFormat
	}
	if state == 2 {
		floor, lower, upper := binary.BigEndian.Uint64(retirement[64:72]), binary.BigEndian.Uint64(retirement[72:80]), binary.BigEndian.Uint64(retirement[80:88])
		// CheckDirectIssue already checked overflow for this exact cohort/grid.
		mature := policy.Origin + (f.Scope.Cohort+1)*policy.Duration + policy.Impact
		if storageZero(retirement[:32]) || storageZero(retirement[32:64]) || floor <= f.Scope.Cohort || lower > upper || lower < mature {
			return false, ErrStorageFormat
		}
	}
	return state == 2, nil
}

func (s *sqliteStore) inspectDirectIssueRecords(epoch uint64, decoder *protocolv4.StorageFactsDecoder) (err error) {
	policy, expected, err := s.inspectDirectIssueConfiguration(decoder)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := s.querier.QueryContext(context.Background(), `SELECT lease,request,invocation,fence,state,version,artifact,
CASE WHEN length(projection) BETWEEN 1 AND 4096 AND length(projection)<=?1 THEN projection ELSE NULL END,retirement
FROM issuance ORDER BY lease`, []driver.NamedValue{named(1, int64(s.backing.limits.MaxRecordBytes))})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [9]driver.Value
	var count uint32
	var active uint64
	for {
		if err = rows.Next(values[:]); err == io.EOF {
			if active != expected {
				return ErrStorageFormat
			}
			return nil
		} else if err != nil {
			return err
		}
		count++
		if count > s.backing.limits.MaxRecords {
			return ErrStorageFormat
		}
		retired, err := s.inspectDirectIssueRecord(values[:], epoch, policy, decoder)
		if err != nil {
			return err
		}
		if !retired {
			active++
		}
	}
}
