package ledgerv4

import (
	"encoding/binary"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

const (
	admissionReserved = iota
	admissionAdmitted
	admissionExpired
	admissionRejected
	admissionKeyBytes = 161
)

// AdmissionOwner names the actual original Acceptor invocation and carrier.
// It is generated once by trusted local assembly, never decoded from a query,
// receipt or peer input. Epoch is separately supplied by the durable authority.
type AdmissionOwner struct {
	Acceptor, Invocation, Carrier [16]byte
	Generation                    uint64
}

func (o AdmissionOwner) valid() bool {
	return o.Acceptor != ([16]byte{}) && o.Invocation != ([16]byte{}) && o.Carrier != ([16]byte{}) && o.Generation != 0
}

type admissionRecord struct {
	fields                                       protocolv4.AdmissionFields
	owner                                        AdmissionOwner
	authority                                    string
	storeID                                      [32]byte
	storeGeneration, fence, deadline, reservedAt uint64
}

// This is a fixed local storage encoding, not another wire protocol. The
// manifest revision owns this layout; Open never dispatches an older decoder.
func (r *admissionRecord) encode(dst []byte, state byte, terminalAt uint64, reservation [32]byte) (int, error) {
	w := admissionWriter{dst: dst}
	w.text("flowersec/admission/1")
	w.bytes([]byte{state})
	version := uint64(1)
	if state != admissionReserved {
		version = 2
	}
	for _, n := range []uint64{version, r.fence, r.storeGeneration, r.owner.Generation, r.deadline, r.reservedAt, terminalAt} {
		w.uint(n)
	}
	for _, b := range [][]byte{r.storeID[:], r.owner.Acceptor[:], r.owner.Invocation[:], r.owner.Carrier[:], reservation[:]} {
		w.bytes(b)
	}
	f := r.fields
	for _, s := range []string{r.authority, f.Tenant, f.Audience, f.Profile, f.Source, f.SpendAuthority, f.WinnerAuthority, f.SigningKey} {
		w.text(s)
	}
	for _, b := range [][]byte{f.Issuer[:], f.Lease[:], f.Attempt[:], f.Candidate[:], f.Artifact[:], f.Proof[:], f.SessionNonce[:], f.ClientIdentity[:], f.ServerIdentity[:], f.AdmissionBinding[:], f.HelloTranscript[:], f.TransportContext[:], f.AdmissionNonce[:], f.Route[:]} {
		w.bytes(b)
	}
	for _, n := range []uint64{f.CandidateIndex, f.IssuedAt, f.ActivationEnd, f.SessionEnd, f.Features, f.BindingMode} {
		w.uint(n)
	}
	return w.n, w.err
}

func (r *admissionRecord) key(dst []byte) (int, error) {
	if len(r.fields.Tenant) == 0 || len(r.fields.Tenant) > 128 || len(dst) < 33+len(r.fields.Tenant) {
		return 0, ErrConfiguration
	}
	dst[0] = byte(len(r.fields.Tenant))
	n := 1 + copy(dst[1:], r.fields.Tenant)
	n += copy(dst[n:], r.fields.Issuer[:])
	n += copy(dst[n:], r.fields.Lease[:])
	return n, nil
}

type admissionWriter struct {
	dst []byte
	n   int
	err error
}

func (w *admissionWriter) bytes(b []byte) {
	if w.err != nil {
		return
	}
	if len(b) > len(w.dst)-w.n {
		w.err = ErrCapacity
		return
	}
	w.n += copy(w.dst[w.n:], b)
}
func (w *admissionWriter) uint(n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	w.bytes(b[:])
}
func (w *admissionWriter) text(s string) {
	if len(s) > 65535 {
		w.err = ErrConfiguration
		return
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(s)))
	w.bytes(b[:])
	if w.err != nil {
		return
	}
	if len(s) > len(w.dst)-w.n {
		w.err = ErrCapacity
		return
	}
	w.n += copy(w.dst[w.n:], s)
}
