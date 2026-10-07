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

// These readers inspect the one current physical representation. They return
// no authenticated credential, dispatch guard or original owner capability.
func storageFactsError(err error) error {
	if err != nil {
		return ErrStorageFormat
	}
	return nil
}
func storageText(r *topUpReader) string {
	prefix := r.take(2)
	if len(prefix) != 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(prefix))
	if n > 128 {
		r.err = ErrStorageFormat
		return ""
	}
	return string(r.take(n))
}
func storageParentKey(key []byte, tenant string, issuer, lease []byte) bool {
	return len(tenant) > 0 && len(tenant) <= 128 && len(key) == 33+len(tenant) &&
		int(key[0]) == len(tenant) && string(key[1:1+len(tenant)]) == tenant &&
		bytes.Equal(key[1+len(tenant):17+len(tenant)], issuer) && bytes.Equal(key[17+len(tenant):], lease)
}
func (s *sqliteStore) inspectAdmissionRecord(key, wire []byte, epoch, version, fence uint64, state int64) error {
	r := topUpReader{data: wire}
	if storageText(&r) != "flowersec/admission/1" {
		return ErrStorageFormat
	}
	encodedState := r.take(1)
	storedVersion, storedFence, generation, ownerGeneration := r.uint(), r.uint(), r.uint(), r.uint()
	deadline, reservedAt, terminalAt := r.uint(), r.uint(), r.uint()
	storeID := r.take(32)
	acceptor, invocation, carrier, reservation := r.take(16), r.take(16), r.take(16), r.take(32)
	var names [8]string
	for i := range names {
		names[i] = storageText(&r)
	}
	issuer, lease := r.take(16), r.take(16)
	_ = r.take(16)
	_ = r.take(16)
	for i := 0; i < 11; i++ {
		_ = r.take(32)
	}
	candidate, issuedAt, activationEnd, sessionEnd := r.uint(), r.uint(), r.uint(), r.uint()
	_ = r.uint()
	bindingMode := r.uint()
	if r.done() != nil || len(encodedState) != 1 || int64(encodedState[0]) != state || storedVersion != version ||
		storedFence != fence || fence == 0 || fence > epoch || generation != s.identity.Generation || ownerGeneration == 0 ||
		!bytes.Equal(storeID, s.identity.StoreID[:]) || names[0] != s.identity.Authority ||
		!storageParentKey(key, names[1], issuer, lease) || (names[4] != "live_authority" && names[4] != "preauthorized_pool") ||
		bytes.Equal(acceptor, make([]byte, 16)) || bytes.Equal(invocation, make([]byte, 16)) || bytes.Equal(carrier, make([]byte, 16)) ||
		deadline <= reservedAt || reservedAt < issuedAt || issuedAt >= activationEnd || activationEnd > sessionEnd || deadline > activationEnd ||
		candidate >= 16 || bindingMode > 1 || (state == admissionReserved && (version != 1 || terminalAt != 0 || !bytes.Equal(reservation, make([]byte, 32)))) ||
		(state != admissionReserved && (version != 2 || terminalAt < reservedAt || bytes.Equal(reservation, make([]byte, 32)))) {
		return ErrStorageFormat
	}
	return nil
}
func (s *sqliteStore) inspectPoolConsume(key, wire []byte, epoch, version, fence uint64, decoder *protocolv4.StorageFactsDecoder) error {
	r := topUpReader{data: wire}
	if storageText(&r) != "flowersec/pool-consume/1" {
		return ErrStorageFormat
	}
	var numbers [17]uint64
	for i := range numbers {
		numbers[i] = r.uint()
	}
	var names [7]string
	for i := range names {
		names[i] = storageText(&r)
	}
	storeID, connect, carrier := r.take(32), r.take(16), r.take(16)
	var facts protocolv4.StoredActivationFacts
	f := &facts.AdmissionFields
	for _, dst := range [][]byte{f.Issuer[:], f.Lease[:], f.Attempt[:], f.Candidate[:], f.Route[:], f.Artifact[:], f.Proof[:], f.SessionNonce[:], f.ClientIdentity[:], f.ServerIdentity[:], f.CandidateSet[:], facts.RouteSet[:]} {
		copy(dst, r.take(len(dst)))
	}
	proofBytes := r.uint()
	if proofBytes == 0 || proofBytes > uint64(len(wire)) {
		return ErrStorageFormat
	}
	proof := r.take(int(proofBytes))
	if r.done() != nil || version != 1 || numbers[0] != version || numbers[1] != fence || fence == 0 || fence > epoch ||
		numbers[2] != s.identity.Generation || numbers[3] == 0 || numbers[4] <= numbers[5] || numbers[4] > numbers[7] ||
		numbers[5] < numbers[6] || numbers[6] >= numbers[7] || numbers[7] > numbers[8] || numbers[9] >= 16 ||
		names[0] != s.identity.Authority || !bytes.Equal(storeID, s.identity.StoreID[:]) ||
		bytes.Equal(connect, make([]byte, 16)) || bytes.Equal(carrier, make([]byte, 16)) ||
		!storageParentKey(key, names[1], f.Issuer[:], f.Lease[:]) {
		return ErrStorageFormat
	}
	f.Source, f.Tenant, f.Audience, f.Profile, f.SpendAuthority, f.WinnerAuthority, f.SigningKey = "preauthorized_pool", names[1], names[2], names[3], names[4], names[5], names[6]
	f.IssuedAt, f.ActivationEnd, f.SessionEnd, f.CandidateIndex = numbers[6], numbers[7], numbers[8], numbers[9]
	facts.Budget = protocolv4.PoolAttemptLimits{CandidateAddressAttempts: numbers[10], CandidatePreauthBytes: numbers[11], CandidateWorkUnits: numbers[12], TotalAddressAttempts: numbers[13], TotalPreauthBytes: numbers[14], TotalWorkUnits: numbers[15], ParallelCandidates: numbers[16]}
	return storageFactsError(decoder.CheckActivation(proof, facts))
}
func inspectParentSelection(key, wire []byte) error {
	f, err := decodeStorageParentSelection(key, wire)
	if err != nil || f.Source != "preauthorized_pool" {
		return ErrStorageFormat
	}
	return nil
}
func decodeStorageParentSelection(key, wire []byte) (f protocolv4.AdmissionFields, err error) {
	r := topUpReader{data: wire}
	if storageText(&r) != "flowersec/parent-winner/3" {
		return f, ErrStorageFormat
	}
	f.Source, f.Tenant, f.WinnerAuthority, f.Audience = storageText(&r), storageText(&r), storageText(&r), storageText(&r)
	for _, dst := range [][]byte{f.Issuer[:], f.Lease[:], f.Artifact[:], f.Proof[:], f.CandidateSet[:], f.Candidate[:], f.Route[:], f.Attempt[:], f.ClientIdentity[:], f.ServerIdentity[:]} {
		copy(dst, r.take(len(dst)))
	}
	f.IssuedAt, f.ActivationEnd, f.SessionEnd = r.uint(), r.uint(), r.uint()
	if r.done() != nil || f.Audience == "" || !storageParentKey(key, f.Tenant, f.Issuer[:], f.Lease[:]) || f.IssuedAt >= f.ActivationEnd || f.ActivationEnd > f.SessionEnd ||
		(f.Source == "preauthorized_pool" && (f.WinnerAuthority == "" || f.CandidateSet == ([32]byte{}))) ||
		(f.Source == "live_authority" && (f.WinnerAuthority != "" || f.CandidateSet != ([32]byte{}))) ||
		(f.Source != "preauthorized_pool" && f.Source != "live_authority") {
		return f, ErrStorageFormat
	}
	return f, nil
}
func (s *sqliteStore) inspectMainRecords(epoch uint64) error {
	decoder, err := protocolv4.NewStorageFactsDecoder()
	if err != nil {
		return err
	}
	for _, table := range []string{"admission", "spend", "parent_winner"} {
		if err := s.inspectMainTable(table, epoch, decoder); err != nil {
			return err
		}
	}
	if err := s.inspectRelayRecords(epoch, decoder); err != nil {
		return err
	}
	if err := s.inspectRelayRegistrations(decoder); err != nil {
		return err
	}
	return s.inspectDirectIssueRecords(epoch, decoder)
}
func (s *sqliteStore) inspectMainTable(table string, epoch uint64, decoder *protocolv4.StorageFactsDecoder) (err error) {
	columns := "version,fence,state,0"
	if table == "spend" {
		columns = "version,fence,state,source"
	}
	if table == "parent_winner" {
		columns = "x'0000000000000000',x'0000000000000000',0,0"
	}
	rows, err := s.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(lease) BETWEEN 34 AND 161 THEN lease ELSE NULL END,CASE WHEN length(projection) BETWEEN 1 AND ?1 THEN projection ELSE NULL END,"+columns+" FROM "+table+" ORDER BY lease", []driver.NamedValue{named(1, int64(s.backing.limits.MaxRecordBytes))})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [6]driver.Value
	var count uint32
	for {
		if err = rows.Next(values[:]); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		count++
		if count > s.backing.limits.MaxRecords {
			return ErrStorageFormat
		}
		key, kok := values[0].([]byte)
		wire, wok := values[1].([]byte)
		version, ve := readSQLiteUint(values[2])
		fence, fe := readSQLiteUint(values[3])
		state, sok := values[4].(int64)
		source, sourceOK := values[5].(int64)
		if !kok || !wok || ve != nil || fe != nil || !sok || !sourceOK {
			return ErrStorageFormat
		}
		switch table {
		case "admission":
			err = s.inspectAdmissionRecord(key, wire, epoch, version, fence, state)
		case "parent_winner":
			err = inspectParentSelection(key, wire)
		case "spend":
			if source == 1 {
				if state != 1 {
					return ErrStorageFormat
				}
				err = s.inspectPoolConsume(key, wire, epoch, version, fence, decoder)
			} else if source == 0 {
				var record liveSpendRecord
				if state == 0 {
					record, err = decodeLiveSpending(wire)
					record.version = 1
					record.fence = record.originalFence
				} else if state == 1 {
					record, err = decodeLiveConsumed(wire)
				} else {
					return ErrStorageFormat
				}
				if err == nil && (record.version != version || record.fence != fence || fence == 0 || fence > epoch || record.authority != s.identity.Authority ||
					record.storeID != s.identity.StoreID || record.storeGeneration != s.identity.Generation || !storageParentKey(key, record.tenant, record.issuer[:], record.lease[:])) {
					err = ErrStorageFormat
				}
			} else {
				return ErrStorageFormat
			}
		}
		if err != nil {
			return err
		}
	}
}
