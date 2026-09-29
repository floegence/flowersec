package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
)

// liveSpendRecord borrows the reader's single charged row buffer. The original
// intent remains intact in a terminal row, including its immutable owner/fence.
type liveSpendRecord struct {
	version                                                         uint64
	found, consumed                                                 bool
	tunnel                                                          bool
	outcome, fence, originalFence, storeGeneration, ownerGeneration uint64
	claimEnd, materialEnd, startedAt, terminalAt, candidateIndex    uint64
	parentInitiationEnd, parentSessionEnd                           uint64
	authority, tenant, audience                                     string
	storeID                                                         [32]byte
	invocation, issuer, lease, attempt                              [16]byte
	request, intent, route, artifact, signer, client, server        [32]byte
	candidate                                                       [16]byte
	projection, spending, unsigned, proof                           []byte
	unsignedGrants, grants                                          [2][]byte
	grantSigners                                                    [2][32]byte
}

func decodeLiveSpending(wire []byte) (v liveSpendRecord, err error) {
	r := topUpReader{data: wire}
	format := r.text()
	if format != "flowersec/live-spending/2" && format != "flowersec/live-spending/3" || r.uint() != 1 {
		return v, ErrStorageFormat
	}
	v.tunnel = format == "flowersec/live-spending/3"
	v.originalFence, v.storeGeneration, v.ownerGeneration = r.uint(), r.uint(), r.uint()
	v.claimEnd, v.materialEnd, v.startedAt, v.candidateIndex = r.uint(), r.uint(), r.uint(), r.uint()
	v.parentInitiationEnd, v.parentSessionEnd = r.uint(), r.uint()
	v.authority, v.tenant, v.audience = r.text(), r.text(), r.text()
	for _, dst := range [][]byte{v.storeID[:], v.invocation[:], v.request[:], v.intent[:], v.candidate[:], v.route[:], v.artifact[:], v.signer[:], v.issuer[:], v.lease[:], v.attempt[:], v.client[:], v.server[:]} {
		copy(dst, r.take(len(dst)))
	}
	n := r.uint()
	if n == 0 || n > uint64(len(wire)) {
		return v, ErrStorageFormat
	}
	if v.parentInitiationEnd < v.materialEnd || v.parentSessionEnd < v.parentInitiationEnd {
		return v, ErrStorageFormat
	}
	v.unsigned = r.take(int(n))
	if v.tunnel {
		for side := range v.unsignedGrants {
			copy(v.grantSigners[side][:], r.take(32))
			n := r.uint()
			if n == 0 || n > uint64(len(wire)) || v.grantSigners[side] == ([32]byte{}) {
				return v, ErrStorageFormat
			}
			v.unsignedGrants[side] = r.take(int(n))
		}
	}
	if err = r.done(); err != nil {
		return v, err
	}
	if v.originalFence == 0 || v.storeGeneration == 0 || v.ownerGeneration == 0 || v.claimEnd <= v.startedAt || v.materialEnd < v.claimEnd || v.authority == "" || v.tenant == "" || v.audience == "" || v.storeID == ([32]byte{}) || v.invocation == ([16]byte{}) || v.request == ([32]byte{}) || v.intent == ([32]byte{}) || v.issuer == ([16]byte{}) || v.lease == ([16]byte{}) || v.attempt == ([16]byte{}) || v.signer == ([32]byte{}) {
		return v, ErrStorageFormat
	}
	v.spending = wire
	return v, nil
}

func encodeLiveConsumed(dst, spending, proof []byte, fence, outcome, terminalAt uint64) (int, error) {
	return encodeLiveConsumedVersion(dst, spending, proof, fence, outcome, terminalAt, 2)
}

func encodeLiveConsumedVersion(dst, spending, proof []byte, fence, outcome, terminalAt, version uint64) (int, error) {
	return encodeLiveMaterial(dst, spending, proof, [2][]byte{}, fence, outcome, terminalAt, version)
}

func encodeLiveMaterial(dst, spending, proof []byte, grants [2][]byte, fence, outcome, terminalAt, version uint64) (int, error) {
	if fence == 0 || outcome > 3 || terminalAt == 0 || outcome != 2 && len(proof) != 0 || version < 2 || version > 3 || version == 3 && (outcome != 1 && outcome != 2 || len(proof) != 0) {
		return 0, ErrConfiguration
	}
	view, err := decodeLiveSpending(spending)
	if err != nil {
		return 0, err
	}
	for _, grant := range grants {
		if len(grant) != 0 && (!view.tunnel || len(proof) == 0 || outcome != 2 || version != 2) {
			return 0, ErrConfiguration
		}
	}
	if view.tunnel && len(proof) != 0 && (len(grants[0]) == 0 || len(grants[1]) == 0) {
		return 0, ErrConfiguration
	}
	w := admissionWriter{dst: dst}
	format := "flowersec/live-consumed/1"
	if view.tunnel {
		format = "flowersec/live-consumed/2"
	}
	w.text(format)
	for _, n := range []uint64{version, fence, outcome, terminalAt, uint64(len(spending))} {
		w.uint(n)
	}
	w.bytes(spending)
	w.uint(uint64(len(proof)))
	w.bytes(proof)
	if view.tunnel {
		for _, grant := range grants {
			w.uint(uint64(len(grant)))
			w.bytes(grant)
		}
	}
	return w.n, w.err
}

func decodeLiveConsumed(wire []byte) (v liveSpendRecord, err error) {
	r := topUpReader{data: wire}
	format := r.text()
	if format != "flowersec/live-consumed/1" && format != "flowersec/live-consumed/2" {
		return v, ErrStorageFormat
	}
	version := r.uint()
	if version < 2 || version > 3 {
		return v, ErrStorageFormat
	}
	fence, outcome, terminalAt, n := r.uint(), r.uint(), r.uint(), r.uint()
	if n == 0 || n > uint64(len(wire)) {
		return v, ErrStorageFormat
	}
	v, err = decodeLiveSpending(r.take(int(n)))
	if err != nil {
		return v, err
	}
	if v.tunnel != (format == "flowersec/live-consumed/2") {
		return v, ErrStorageFormat
	}
	n = r.uint()
	if n > uint64(len(wire)) {
		return v, ErrStorageFormat
	}
	v.proof = r.take(int(n))
	if v.tunnel {
		for side := range v.grants {
			n := r.uint()
			if n > uint64(len(wire)) {
				return v, ErrStorageFormat
			}
			v.grants[side] = r.take(int(n))
			if (len(v.grants[side]) == 0) != (len(v.proof) == 0) {
				return v, ErrStorageFormat
			}
		}
	}
	if err = r.done(); err != nil {
		return v, err
	}
	if fence < v.originalFence || outcome > 3 || terminalAt < v.startedAt || outcome != 2 && len(v.proof) != 0 || version == 3 && (outcome != 1 && outcome != 2 || len(v.proof) != 0) {
		return v, ErrStorageFormat
	}
	v.consumed, v.fence, v.outcome, v.terminalAt = true, fence, outcome, terminalAt
	v.version = version
	return v, nil
}

func (s *sqliteStore) readLiveSpend(key, dst []byte) (v liveSpendRecord, err error) {
	rows, err := s.querier.QueryContext(context.Background(), "SELECT source,state,version,fence,length(projection),CASE WHEN length(projection)<=?2 THEN projection ELSE NULL END FROM spend WHERE lease=?1", []driver.NamedValue{named(1, key), named(2, int64(len(dst)))})
	if err != nil {
		return v, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [6]driver.Value
	if err = rows.Next(values[:]); err == io.EOF {
		return v, nil
	} else if err != nil {
		return v, err
	}
	version, ve := readSQLiteUint(values[2])
	fence, fe := readSQLiteUint(values[3])
	wire, ok := values[5].([]byte)
	if ve != nil || fe != nil || !ok || len(wire) == 0 || len(wire) > len(dst) || values[4] != int64(len(wire)) {
		return v, ErrStorageFormat
	}
	if values[0] != int64(0) {
		return v, ErrConflict
	}
	wire = dst[:copy(dst, wire)]
	switch values[1] {
	case int64(0):
		if version != 1 {
			return v, ErrStorageFormat
		}
		v, err = decodeLiveSpending(wire)
		v.fence = v.originalFence
		v.version = 1
	case int64(1):
		if version < 2 || version > 3 {
			return v, ErrStorageFormat
		}
		v, err = decodeLiveConsumed(wire)
	default:
		return v, ErrStorageFormat
	}
	if err != nil {
		return v, err
	}
	v.projection = wire
	if v.version != version || v.fence != fence || fence > s.epoch || v.authority != s.identity.Authority || v.storeID != s.identity.StoreID || v.storeGeneration != s.identity.Generation {
		return v, ErrStorageFormat
	}
	var expected [admissionKeyBytes]byte
	expected[0] = byte(len(v.tenant))
	size := 1 + copy(expected[1:], v.tenant)
	size += copy(expected[size:], v.issuer[:])
	size += copy(expected[size:], v.lease[:])
	if !bytes.Equal(key, expected[:size]) {
		return v, ErrStorageFormat
	}
	if err = rows.Next(values[:]); err != io.EOF {
		return v, ErrStorageFormat
	}
	v.found = true
	return v, nil
}
