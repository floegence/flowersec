package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func storageSizedBytes(r *topUpReader, limit uint64) []byte {
	n := r.uint()
	if n == 0 || n > limit || n > uint64(len(r.data)-r.n) {
		r.err = ErrStorageFormat
		return nil
	}
	return r.take(int(n))
}

func storageZero(wire []byte) bool {
	for _, b := range wire {
		if b != 0 {
			return false
		}
	}
	return true
}

type storedRelayRoot struct {
	fields                     protocolv4.AdmissionFields
	selection, parent          []byte
	service, audience, profile string
	pairing                    [16]byte
	relay, contract            [32]byte
}

func inspectRelayRoot(key, wire []byte, decoder *protocolv4.StorageFactsDecoder) (root storedRelayRoot, err error) {
	r := topUpReader{data: wire}
	if storageText(&r) != "flowersec/relay-parent/1" {
		return root, ErrStorageFormat
	}
	root.selection = storageSizedBytes(&r, uint64(len(wire)))
	root.fields, err = decodeStorageParentSelection(key, root.selection)
	if err != nil {
		return root, err
	}
	root.service, root.audience, root.profile = storageText(&r), storageText(&r), storageText(&r)
	copy(root.pairing[:], r.take(16))
	copy(root.relay[:], r.take(32))
	copy(root.contract[:], r.take(32))
	root.parent = storageSizedBytes(&r, 65536)
	if r.done() != nil || root.service == "" || root.audience == "" || root.profile == "" {
		return root, ErrStorageFormat
	}
	return root, storageFactsError(decoder.CheckRelayParent(root.parent, root.fields))
}

func (s *sqliteStore) inspectRelayLeg(wire, parent []byte, root storedRelayRoot, epoch, fence, side uint64, decoder *protocolv4.StorageFactsDecoder) error {
	r := topUpReader{data: wire}
	if storageText(&r) != "flowersec/relay-leg/1" || !bytes.Equal(storageSizedBytes(&r, uint64(len(wire))), parent) || storageText(&r) != s.identity.Authority {
		return ErrStorageFormat
	}
	storeID, owner, invocation, carrier, possession, challenge := r.take(32), r.take(16), r.take(16), r.take(16), r.take(32), r.take(32)
	generation, storedFence, version, ownerGeneration, storedSide, deadline := r.uint(), r.uint(), r.uint(), r.uint(), r.uint(), r.uint()
	grant := storageSizedBytes(&r, 65536)
	if r.done() != nil || !bytes.Equal(storeID, s.identity.StoreID[:]) || generation != s.identity.Generation || storedFence != fence || fence == 0 || fence > epoch || version != 1 || ownerGeneration == 0 || storedSide != side || storageZero(owner) || storageZero(invocation) || storageZero(carrier) || storageZero(possession) || storageZero(challenge) || deadline <= root.fields.IssuedAt || deadline > root.fields.ActivationEnd {
		return ErrStorageFormat
	}
	return storageFactsError(decoder.CheckRelayGrant(grant, root.parent, root.fields, root.service, root.audience, root.pairing, root.relay, root.contract, side, deadline))
}

func (s *sqliteStore) inspectRelayRecords(epoch uint64, decoder *protocolv4.StorageFactsDecoder) (err error) {
	rows, err := s.querier.QueryContext(context.Background(), `SELECT p.lease,
CASE WHEN length(p.projection) BETWEEN 1 AND ?1 THEN p.projection ELSE NULL END,
l.side,l.claimed,l.version,l.fence,
CASE WHEN length(l.projection) BETWEEN 1 AND ?1 THEN l.projection ELSE NULL END,
length(w.projection),w.projection=substr(p.projection,?2,length(w.projection))
FROM relay_parent p JOIN relay_leg l ON l.lease=p.lease LEFT JOIN parent_winner w ON w.lease=p.lease ORDER BY p.lease,l.side`, []driver.NamedValue{named(1, int64(s.backing.limits.MaxRecordBytes)), named(2, int64(2+len("flowersec/relay-parent/1")+8+1))})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [9]driver.Value
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
		parent, pok := values[1].([]byte)
		side, sok := values[2].(int64)
		claimed, cok := values[3].(int64)
		version, ve := readSQLiteUint(values[4])
		fence, fe := readSQLiteUint(values[5])
		wire, wok := values[6].([]byte)
		if !kok || !pok || !sok || side < 0 || side > 1 || !cok || !wok || ve != nil || fe != nil {
			return ErrStorageFormat
		}
		root, err := inspectRelayRoot(key, parent, decoder)
		if err != nil {
			return err
		}
		if root.fields.Source == "preauthorized_pool" {
			if values[7] != int64(len(root.selection)) || values[8] != int64(1) || root.fields.WinnerAuthority != s.identity.Authority {
				return ErrStorageFormat
			}
		}
		if claimed == 0 {
			if version != 0 || fence != 0 || len(wire) != int(s.backing.limits.MaxRecordBytes) || !storageZero(wire) {
				return ErrStorageFormat
			}
		} else if claimed == 1 {
			if version != 1 {
				return ErrStorageFormat
			}
			if err := s.inspectRelayLeg(wire, parent, root, epoch, fence, uint64(side), decoder); err != nil {
				return err
			}
		} else {
			return ErrStorageFormat
		}
	}
}

func inspectRelayRegistrationSources(wire []byte) error {
	r := topUpReader{data: wire}
	for i := 0; i < 2; i++ {
		prefix := r.take(1)
		if len(prefix) != 1 || prefix[0] == 0 || prefix[0] > 128 {
			return ErrStorageFormat
		}
		identity := SQLiteIdentity{Authority: string(r.take(int(prefix[0])))}
		copy(identity.StoreID[:], r.take(32))
		identity.Generation = r.uint()
		if !validSQLiteIdentity(identity) {
			return ErrStorageFormat
		}
	}
	return r.done()
}

func (s *sqliteStore) inspectRelayRegistrations(decoder *protocolv4.StorageFactsDecoder) (err error) {
	rows, err := s.querier.QueryContext(context.Background(), `SELECT selection,sources,state,invocation,digest,
CASE WHEN length(projection) BETWEEN 1 AND ?1 AND length(projection)<=65536 THEN projection ELSE NULL END
FROM relay_issuance ORDER BY selection`, []driver.NamedValue{named(1, int64(s.backing.limits.MaxRecordBytes))})
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
		sources, sok := values[1].([]byte)
		state, stateOK := values[2].(int64)
		invocation, iok := values[3].([]byte)
		digest, dok := values[4].([]byte)
		wire, wok := values[5].([]byte)
		if !kok || len(key) < 66 || len(key) > 193 || int(key[0])+65 != len(key) || key[0] == 0 || key[0] > 128 || !sok || !stateOK || !iok || len(invocation) != 16 || !dok || len(digest) != 32 || !wok {
			return ErrStorageFormat
		}
		for offset := 1 + int(key[0]); offset < len(key); offset += 16 {
			if storageZero(key[offset : offset+16]) {
				return ErrStorageFormat
			}
		}
		if err := inspectRelayRegistrationSources(sources); err != nil {
			return err
		}
		if state == 0 {
			if storageZero(invocation) || !storageZero(digest) || len(wire) != 65536 || !storageZero(wire) {
				return ErrStorageFormat
			}
			continue
		}
		if state != 1 {
			return ErrStorageFormat
		}
		expected := relayRegistrationDigest(key, sources, wire)
		if !bytes.Equal(digest, expected[:]) {
			return ErrStorageFormat
		}
		selection, err := decoder.InspectRelayRecord(wire)
		if err != nil {
			return ErrStorageFormat
		}
		var backing [193]byte
		encoded, err := relayRegistrationKey(backing[:], selection)
		if err != nil || !bytes.Equal(encoded, key) {
			return ErrStorageFormat
		}
	}
}
