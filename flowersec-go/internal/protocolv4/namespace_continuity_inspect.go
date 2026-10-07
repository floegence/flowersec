package protocolv4

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
)

// InspectNamespaceContinuityRecord admits the current storage envelope without
// retaining its potentially large opaque signed objects. Signature, trust and
// freshness checks remain with the original namespace restore owner. Returned
// metadata is detached and carries no restored verification authority.
func InspectNamespaceContinuityRecord(source io.Reader, size uint64, limits NamespaceContinuityLimits) (out NamespaceContinuityRecord, err error) {
	maximum, err := NamespaceContinuityRecordBytes(limits)
	if err != nil || size > maximum || size > math.MaxInt64 || source == nil {
		return out, CBORFailure("revocation_continuity_record")
	}
	r := namespaceInspectionReader{source: io.LimitedReader{R: source, N: int64(size)}}
	if !bytes.Equal(r.take(uint64(len(namespaceContinuityMagic))), []byte(namespaceContinuityMagic)) {
		return out, CBORFailure("revocation_continuity_record")
	}
	out.StorageSchemaRevision = r.uint()
	out.Tenant = r.text(maxNamespaceContinuityIdentityBytes)
	out.Authority = r.text(maxNamespaceContinuityIdentityBytes)
	copy(out.CapacityDigest[:], r.take(32))
	out.WireProfile = r.text(maxNamespaceContinuityProfileBytes)
	bound := out.StorageSchemaRevision != 0 || out.Tenant != "" || out.Authority != "" || out.CapacityDigest != ([32]byte{}) || out.WireProfile != ""
	if bound && (out.StorageSchemaRevision != namespaceContinuityStorageSchemaRevision || !continuityIdentity(out.Tenant) || !continuityIdentity(out.Authority) || out.CapacityDigest == ([32]byte{}) || out.WireProfile != namespaceContinuityWireProfile) {
		return out, CBORFailure("revocation_continuity_binding")
	}
	out.FetchDurationMS = r.uint()
	attempts := r.uint()
	out.SettledSequence = r.uint()
	count := r.uint()
	if out.FetchDurationMS != limits.FetchDurationMS || attempts != uint64(limits.FetchAttempts) || count == 0 || count > uint64(limits.TrustConfigurations) {
		return out, CBORFailure("revocation_continuity_record")
	}
	out.FetchAttempts, out.TrustCount = uint8(attempts), uint32(count)
	for i := uint64(0); i < count; i++ {
		if r.blob(uint64(limits.TrustConfigBytes)) == 0 {
			return out, CBORFailure("revocation_continuity_record")
		}
	}
	headMaximum, e := SchemaByteLimit("FreshnessHead")
	if e != nil {
		return out, e
	}
	var pinnedBytes uint64
	for i, head := range []*NamespaceHeadHistory{&out.Active, &out.Observed, &out.Pinned} {
		head.TrustRevision = r.uint()
		n := r.blob(uint64(headMaximum))
		if i < 2 && (head.TrustRevision == 0 || n == 0) || i == 2 && ((head.TrustRevision == 0) != (n == 0)) {
			return out, CBORFailure("revocation_continuity_record")
		}
		if i == 2 {
			pinnedBytes = n
		}
	}
	out.PinnedDeadlineMS = r.uint()
	attempts = r.uint()
	if attempts > math.MaxUint8 || pinnedBytes == 0 && (out.PinnedDeadlineMS != 0 || attempts != 0) || pinnedBytes != 0 && (out.PinnedDeadlineMS == 0 || attempts > uint64(out.FetchAttempts)) {
		return out, CBORFailure("revocation_continuity_record")
	}
	out.PinnedAttempts = uint8(attempts)
	if r.blob(limits.StateBytes) == 0 || r.err != nil || r.source.N != 0 {
		return NamespaceContinuityRecord{}, CBORFailure("revocation_continuity_record")
	}
	return out, nil
}

type namespaceInspectionReader struct {
	source  io.LimitedReader
	scratch [4096]byte
	err     error
}

func (r *namespaceInspectionReader) take(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if n > uint64(len(r.scratch)) || n > uint64(r.source.N) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	_, r.err = io.ReadFull(&r.source, r.scratch[:int(n)])
	if r.err != nil {
		return nil
	}
	return r.scratch[:int(n)]
}
func (r *namespaceInspectionReader) uint() uint64 {
	data := r.take(8)
	if len(data) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(data)
}
func (r *namespaceInspectionReader) text(maximum uint64) string {
	n := r.uint()
	if n > maximum {
		r.err = io.ErrUnexpectedEOF
		return ""
	}
	return string(r.take(n))
}
func (r *namespaceInspectionReader) blob(maximum uint64) uint64 {
	n := r.uint()
	if r.err != nil || n > maximum || n > uint64(r.source.N) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	for remaining := n; remaining > 0; {
		count := min(remaining, uint64(len(r.scratch)))
		if r.take(count) == nil {
			return 0
		}
		remaining -= count
	}
	return n
}
