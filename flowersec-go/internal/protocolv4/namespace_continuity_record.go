package protocolv4

import (
	"bytes"
	"encoding/binary"
	"math"
)

// NamespaceContinuityLimits is trusted local storage configuration. It is not
// a peer-negotiated wire feature and does not change NamespaceCapacity.
type NamespaceContinuityLimits struct {
	TrustConfigurations uint32
	TrustConfigBytes    uint32
	StateBytes          uint64
	FetchDurationMS     uint64
	FetchAttempts       uint8
}

// NamespaceHeadHistory records the original independent TrustConfig revision,
// not whichever trust interval happens to be current when a process restarts.
type NamespaceHeadHistory struct {
	TrustRevision uint64
	Head          []byte
}

// NamespaceContinuityRecord contains complete verification history only. Its
// byte slices borrow the original admitted snapshot until the caller releases
// it. Decoding this record grants no trust or restoration authority: recovery
// must authenticate the store's freshness and reverify all original signatures,
// mappings, denial evidence, frontiers and fixed deadlines with the common
// namespace implementation. It never contains Session keys or execution rights.
type NamespaceContinuityRecord struct {
	// The storage header is part of the record body (rather than only a
	// backend manifest) so a snapshot copied between transaction groups cannot
	// be accepted after a local CheckNamespaceScope call. Zero values are kept
	// decodable for bounded adapter fixtures; durable production publishers set
	// all fields and restore rejects an unbound record.
	StorageSchemaRevision    uint64
	Tenant, Authority        string
	CapacityDigest           [32]byte
	WireProfile              string
	TrustCount               uint32
	Trust                    [64][]byte
	Active, Observed, Pinned NamespaceHeadHistory
	State                    []byte
	SettledSequence          uint64
	PinnedDeadlineMS         uint64
	PinnedAttempts           uint8
	FetchDurationMS          uint64
	FetchAttempts            uint8
}

const namespaceContinuityMagic = "flowersec-v4-verification-1\x00"

const (
	namespaceContinuityStorageSchemaRevision uint64 = 1
	namespaceContinuityWireProfile                  = "flowersec-v4-transport-security"
	maxNamespaceContinuityIdentityBytes             = 128
	maxNamespaceContinuityProfileBytes              = 64
)

// NamespaceContinuityRecordBytes includes every full original trust map and
// the active State, plus all three Head slots and fixed metadata. Digest-only
// records cannot replace issuer impact or member/omission evidence.
func NamespaceContinuityRecordBytes(l NamespaceContinuityLimits) (uint64, error) {
	if l.TrustConfigurations == 0 || l.TrustConfigurations > 64 || l.TrustConfigBytes < 1024 || l.TrustConfigBytes > 262144 || l.StateBytes == 0 || l.StateBytes > 1<<30 || l.FetchDurationMS == 0 || l.FetchDurationMS > 90000 || l.FetchAttempts == 0 {
		return 0, CBORFailure("configuration_capacity")
	}
	head, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return 0, err
	}
	return uint64(len(namespaceContinuityMagic)) + 8*9 + 8 + 2*(8+maxNamespaceContinuityIdentityBytes) + 32 + 8 + maxNamespaceContinuityProfileBytes + uint64(l.TrustConfigurations)*(8+uint64(l.TrustConfigBytes)) + 3*(16+uint64(head)) + l.StateBytes, nil
}

func checkNamespaceContinuityRecord(l NamespaceContinuityLimits, r NamespaceContinuityRecord) error {
	if _, err := NamespaceContinuityRecordBytes(l); err != nil {
		return err
	}
	bound := r.StorageSchemaRevision != 0 || r.Tenant != "" || r.Authority != "" || r.CapacityDigest != ([32]byte{}) || r.WireProfile != ""
	if bound && (r.StorageSchemaRevision != namespaceContinuityStorageSchemaRevision || !continuityIdentity(r.Tenant) || !continuityIdentity(r.Authority) || r.CapacityDigest == ([32]byte{}) || r.WireProfile != namespaceContinuityWireProfile) {
		return CBORFailure("revocation_continuity_binding")
	}
	if r.TrustCount == 0 || r.TrustCount > l.TrustConfigurations || r.FetchDurationMS != l.FetchDurationMS || r.FetchAttempts != l.FetchAttempts || len(r.State) == 0 || uint64(len(r.State)) > l.StateBytes {
		return CBORFailure("revocation_continuity_record")
	}
	for i, trust := range r.Trust {
		if i < int(r.TrustCount) {
			if len(trust) == 0 || uint64(len(trust)) > uint64(l.TrustConfigBytes) {
				return CBORFailure("revocation_continuity_record")
			}
		} else if len(trust) != 0 {
			return CBORFailure("revocation_continuity_record")
		}
	}
	cap, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return err
	}
	for i, h := range [...]NamespaceHeadHistory{r.Active, r.Observed, r.Pinned} {
		if i == 2 && len(h.Head) == 0 {
			if h.TrustRevision != 0 || r.PinnedDeadlineMS != 0 || r.PinnedAttempts != 0 {
				return CBORFailure("revocation_continuity_record")
			}
			continue
		}
		if h.TrustRevision == 0 || len(h.Head) == 0 || len(h.Head) > cap {
			return CBORFailure("revocation_continuity_record")
		}
		if i == 2 && (r.PinnedDeadlineMS == 0 || r.PinnedAttempts > r.FetchAttempts) {
			return CBORFailure("revocation_continuity_record")
		}
	}
	return nil
}

// EncodeNamespaceContinuityRecord writes a versioned private storage record.
// It does not mint a signed map or introduce an L0 serialization variant.
func EncodeNamespaceContinuityRecord(dst []byte, limits NamespaceContinuityLimits, r NamespaceContinuityRecord) (int, error) {
	if err := checkNamespaceContinuityRecord(limits, r); err != nil {
		return 0, err
	}
	w := namespaceRecordWriter{dst: dst}
	w.put([]byte(namespaceContinuityMagic))
	w.uint(r.StorageSchemaRevision)
	w.text(r.Tenant)
	w.text(r.Authority)
	w.put(r.CapacityDigest[:])
	w.text(r.WireProfile)
	w.uint(r.FetchDurationMS)
	w.uint(uint64(r.FetchAttempts))
	w.uint(r.SettledSequence)
	w.uint(uint64(r.TrustCount))
	for _, trust := range r.Trust[:r.TrustCount] {
		w.blob(trust)
	}
	for _, h := range [...]NamespaceHeadHistory{r.Active, r.Observed, r.Pinned} {
		w.uint(h.TrustRevision)
		w.blob(h.Head)
	}
	w.uint(r.PinnedDeadlineMS)
	w.uint(uint64(r.PinnedAttempts))
	w.blob(r.State)
	if w.err != nil {
		clear(dst[:w.n])
		return 0, w.err
	}
	return w.n, nil
}

// DecodeNamespaceContinuityRecord returns bounded borrowed facts and refuses
// trailing, truncated, over-capacity or structurally incomplete storage data.
func DecodeNamespaceContinuityRecord(wire []byte, limits NamespaceContinuityLimits) (out NamespaceContinuityRecord, err error) {
	maximum, err := NamespaceContinuityRecordBytes(limits)
	if err != nil {
		return out, err
	}
	if uint64(len(wire)) > maximum || len(wire) < len(namespaceContinuityMagic) || !bytes.Equal(wire[:len(namespaceContinuityMagic)], []byte(namespaceContinuityMagic)) {
		return out, CBORFailure("revocation_continuity_record")
	}
	r := namespaceRecordReader{wire: wire, n: len(namespaceContinuityMagic)}
	out.StorageSchemaRevision = r.uint()
	out.Tenant = r.text(maxNamespaceContinuityIdentityBytes)
	out.Authority = r.text(maxNamespaceContinuityIdentityBytes)
	capacity := r.take(32)
	if len(capacity) == 32 {
		copy(out.CapacityDigest[:], capacity)
	}
	out.WireProfile = r.text(maxNamespaceContinuityProfileBytes)
	out.FetchDurationMS = r.uint()
	attempts := r.uint()
	out.SettledSequence = r.uint()
	count := r.uint()
	if attempts > math.MaxUint8 || count == 0 || count > uint64(limits.TrustConfigurations) {
		return out, CBORFailure("revocation_continuity_record")
	}
	out.FetchAttempts, out.TrustCount = uint8(attempts), uint32(count)
	for i := range int(count) {
		out.Trust[i] = r.blob(uint64(limits.TrustConfigBytes))
	}
	head, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return out, err
	}
	for _, h := range []*NamespaceHeadHistory{&out.Active, &out.Observed, &out.Pinned} {
		h.TrustRevision = r.uint()
		h.Head = r.blob(uint64(head))
	}
	out.PinnedDeadlineMS = r.uint()
	attempts = r.uint()
	if attempts > math.MaxUint8 {
		return out, CBORFailure("revocation_continuity_record")
	}
	out.PinnedAttempts = uint8(attempts)
	out.State = r.blob(limits.StateBytes)
	if r.err != nil || r.n != len(wire) {
		return NamespaceContinuityRecord{}, CBORFailure("revocation_continuity_record")
	}
	if err = checkNamespaceContinuityRecord(limits, out); err != nil {
		return NamespaceContinuityRecord{}, err
	}
	return out, nil
}

type namespaceRecordWriter struct {
	dst []byte
	n   int
	err error
}

func (w *namespaceRecordWriter) put(b []byte) {
	if w.err != nil {
		return
	}
	if len(b) > len(w.dst)-w.n {
		w.err = CBORFailure("configuration_capacity")
		return
	}
	w.n += copy(w.dst[w.n:], b)
}
func (w *namespaceRecordWriter) uint(n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	w.put(b[:])
}
func (w *namespaceRecordWriter) blob(b []byte) { w.uint(uint64(len(b))); w.put(b) }
func (w *namespaceRecordWriter) text(s string) { w.blob([]byte(s)) }

type namespaceRecordReader struct {
	wire []byte
	n    int
	err  error
}

func (r *namespaceRecordReader) take(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if n > uint64(len(r.wire)-r.n) {
		r.err = CBORFailure("revocation_continuity_record")
		return nil
	}
	b := r.wire[r.n : r.n+int(n) : r.n+int(n)]
	r.n += int(n)
	return b
}
func (r *namespaceRecordReader) uint() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *namespaceRecordReader) blob(maximum uint64) []byte {
	n := r.uint()
	if n > maximum {
		r.err = CBORFailure("revocation_continuity_record")
		return nil
	}
	return r.take(n)
}
func (r *namespaceRecordReader) text(maximum uint64) string {
	b := r.blob(maximum)
	if b == nil && r.err != nil {
		return ""
	}
	return string(b)
}

func continuityIdentity(s string) bool {
	if len(s) == 0 || len(s) > maxNamespaceContinuityIdentityBytes {
		return false
	}
	for _, b := range []byte(s) {
		if b == 0 {
			return false
		}
	}
	return true
}

func (NamespaceContinuityRecord) String() string               { return "Flowersec.NamespaceContinuityRecord" }
func (NamespaceContinuityRecord) GoString() string             { return "Flowersec.NamespaceContinuityRecord" }
func (NamespaceContinuityRecord) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
