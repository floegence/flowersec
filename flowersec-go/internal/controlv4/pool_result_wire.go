package controlv4

import (
	"bytes"
	"encoding/binary"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// PoolControlReply is detached server history, before transport authentication.
// A terminal and an independent permanent source fence are distinct variants;
// unknown request/response history is never synthesized for a source fence.
type PoolControlReply struct {
	Code     protocolv4.V4TopUpWireResult
	Response []byte
	Terminal *ledgerv4.TopUpServerSnapshot
	Fence    *ledgerv4.TopUpPermanentFenceReceipt
}

// EncodePoolControlReply writes the reference application's pool-result-1
// envelope. The original canonical TopUpResponse is a byte string; it is not
// re-encoded. Field layouts are documented in docs/CONTROL_V4_POOL.md.
func EncodePoolControlReply(dst []byte, method uint32, r PoolControlReply) (int, error) {
	if err := validatePoolReply(method, r); err != nil {
		return 0, err
	}
	w := poolWireWriter{dst: dst[:min(len(dst), 524288)]}
	w.array(4)
	w.text(string(r.Code))
	w.blob(r.Response)
	if r.Terminal == nil {
		w.absent()
	} else {
		w.terminal(*r.Terminal)
	}
	if r.Fence == nil {
		w.absent()
	} else {
		w.array(3)
		w.text(r.Fence.Tenant)
		w.blob(r.Fence.Source[:])
		w.uint(r.Fence.Generation)
	}
	if w.err != nil {
		clear(dst[:w.n])
		return 0, w.err
	}
	return w.n, nil
}

func validatePoolReply(method uint32, r PoolControlReply) error {
	if method != ControlPoolTopUp && method != ControlPoolAck || len(r.Response) > 524288 {
		return ErrResponse
	}
	if r.Code == "success" || r.Code == "replay" {
		if r.Terminal != nil || r.Fence != nil || (method == ControlPoolTopUp) != (len(r.Response) != 0) {
			return ErrResponse
		}
		return nil
	}
	code := protocolv4.V4TopUpErrorCode(r.Code)
	if _, ok := protocolv4.TopUpErrorProjection(code, protocolv4.V4TopUpWriteActionNone); !ok || len(r.Response) != 0 || r.Terminal != nil && r.Fence != nil {
		return ErrResponse
	}
	if r.Terminal != nil {
		if r.Terminal.Terminal != code || ledgerv4.CheckTopUpTerminalFacts(*r.Terminal) != nil {
			return ErrResponse
		}
	}
	if r.Fence != nil && (code != protocolv4.V4TopUpErrorCodeSourceResetRequired || len(r.Fence.Tenant) == 0 || len(r.Fence.Tenant) > 128 || r.Fence.Source == ([16]byte{}) || r.Fence.Generation == 0) {
		return ErrResponse
	}
	return nil
}

// This writer handles only the fixed application arrays below. Received CBOR
// always uses the shared canonical decoder, with fixed byte and node limits.
type poolWireWriter struct {
	dst []byte
	n   int
	err error
}

func (w *poolWireWriter) put(p []byte) {
	if w.err != nil {
		return
	}
	if len(p) > len(w.dst)-w.n {
		w.err = ErrResponse
		return
	}
	w.n += copy(w.dst[w.n:], p)
}
func (w *poolWireWriter) head(major byte, n uint64) {
	var b [9]byte
	width := 1
	switch {
	case n < 24:
		b[0] = major<<5 | byte(n)
	case n <= 255:
		b[0], b[1], width = major<<5|24, byte(n), 2
	case n <= 65535:
		b[0], width = major<<5|25, 3
		binary.BigEndian.PutUint16(b[1:3], uint16(n))
	case n <= 4294967295:
		b[0], width = major<<5|26, 5
		binary.BigEndian.PutUint32(b[1:5], uint32(n))
	default:
		b[0], width = major<<5|27, 9
		binary.BigEndian.PutUint64(b[1:], n)
	}
	w.put(b[:width])
}
func (w *poolWireWriter) array(n uint64) { w.head(4, n) }
func (w *poolWireWriter) uint(n uint64)  { w.head(0, n) }
func (w *poolWireWriter) blob(b []byte)  { w.head(2, uint64(len(b))); w.put(b) }
func (w *poolWireWriter) text(s string)  { w.head(3, uint64(len(s))); w.put([]byte(s)) }
func (w *poolWireWriter) absent()        { w.put([]byte{0x80}) }
func (w *poolWireWriter) boolean(b bool) {
	if b {
		w.put([]byte{0xf5})
	} else {
		w.put([]byte{0xf4})
	}
}
func (w *poolWireWriter) terminal(s ledgerv4.TopUpServerSnapshot) {
	w.array(9)
	r := s.Request
	w.array(10)
	w.text(r.Tenant)
	for _, b := range [][]byte{r.Source[:], r.Operation[:], r.Pool[:], r.Identity[:], r.Digest[:]} {
		w.blob(b)
	}
	for _, n := range []uint64{r.Generation, r.DeadlineMS, uint64(r.DesiredCount), uint64(r.MaxItemBytes)} {
		w.uint(n)
	}
	if s.State == ledgerv4.TopUpServerRetired {
		w.text("retired")
	} else {
		w.text("terminal")
	}
	for _, n := range []uint64{s.BindingGeneration, s.NextSequence, s.RetiredSequence, s.HighestArtifact, s.RetiredArtifact} {
		w.uint(n)
	}
	w.boolean(s.Permanent)
	if s.Response.Count == 0 {
		w.absent()
		return
	}
	f := s.Response
	w.array(6)
	w.uint(f.Generation)
	w.uint(f.Highest)
	w.uint(f.RetiredThrough)
	w.boolean(f.Gap)
	w.blob(f.Digest[:])
	w.array(uint64(f.Count))
	for _, e := range f.Entries[:f.Count] {
		w.array(5)
		w.uint(e.Sequence)
		w.uint(e.Generation)
		w.uint(e.ExpiryMS)
		w.blob(e.Material[:])
		w.blob(e.Identity[:])
	}
}

type poolWireReader struct{ err error }

func (r *poolWireReader) array(v protocolv4.Value, n int) {
	b := v.Encoded()
	if len(b) == 0 || b[0]>>5 != 4 || v.Len() != n {
		r.err = ErrResponse
	}
}
func (r *poolWireReader) uint(v protocolv4.Value) uint64 {
	n, ok := v.Uint()
	if !ok {
		r.err = ErrResponse
	}
	return n
}
func (r *poolWireReader) text(v protocolv4.Value) string {
	s, ok := v.Text()
	if !ok || len(s) == 0 || len(s) > 128 {
		r.err = ErrResponse
	}
	return s
}
func (r *poolWireReader) blob(v protocolv4.Value, dst []byte) {
	b, ok := v.ByteString()
	if !ok || len(b) != len(dst) {
		r.err = ErrResponse
		return
	}
	copy(dst, b)
}
func (r *poolWireReader) boolean(v protocolv4.Value) bool {
	b, ok := v.Bool()
	if !ok {
		r.err = ErrResponse
	}
	return b
}
func poolWireAbsent(v protocolv4.Value) bool { return bytes.Equal(v.Encoded(), []byte{0x80}) }
func (r *poolWireReader) terminal(v protocolv4.Value, code protocolv4.V4TopUpErrorCode) (s ledgerv4.TopUpServerSnapshot) {
	r.array(v, 9)
	q := v.Index(0)
	r.array(q, 10)
	p := &s.Request
	p.Tenant = r.text(q.Index(0))
	for i, b := range [][]byte{p.Source[:], p.Operation[:], p.Pool[:], p.Identity[:], p.Digest[:]} {
		r.blob(q.Index(i+1), b)
	}
	p.Generation, p.DeadlineMS = r.uint(q.Index(6)), r.uint(q.Index(7))
	count, size := r.uint(q.Index(8)), r.uint(q.Index(9))
	if count < 1 || count > 4 || size < 1 || size > 65536 || p.Generation == 0 || p.DeadlineMS == 0 || p.Source == ([16]byte{}) {
		r.err = ErrResponse
	}
	p.DesiredCount, p.MaxItemBytes = uint32(count), uint32(size)
	switch r.text(v.Index(1)) {
	case "terminal":
		s.State = ledgerv4.TopUpServerTerminal
	case "retired":
		s.State = ledgerv4.TopUpServerRetired
	default:
		r.err = ErrResponse
	}
	for i, dst := range []*uint64{&s.BindingGeneration, &s.NextSequence, &s.RetiredSequence, &s.HighestArtifact, &s.RetiredArtifact} {
		*dst = r.uint(v.Index(i + 2))
	}
	s.Permanent = r.boolean(v.Index(7))
	s.Terminal = code
	if poolWireAbsent(v.Index(8)) {
		return s
	}
	f := &s.Response
	x := v.Index(8)
	r.array(x, 6)
	f.Tenant, f.Source, f.Operation = p.Tenant, p.Source, p.Operation
	f.Generation, f.Highest, f.RetiredThrough = r.uint(x.Index(0)), r.uint(x.Index(1)), r.uint(x.Index(2))
	f.Gap = r.boolean(x.Index(3))
	r.blob(x.Index(4), f.Digest[:])
	items := x.Index(5)
	count = uint64(items.Len())
	if count < 1 || count > 4 {
		r.err = ErrResponse
		return s
	}
	r.array(items, int(count))
	f.Count = uint32(count)
	for i := range int(count) {
		x := items.Index(i)
		r.array(x, 5)
		e := &f.Entries[i]
		e.Sequence, e.Generation, e.ExpiryMS = r.uint(x.Index(0)), r.uint(x.Index(1)), r.uint(x.Index(2))
		r.blob(x.Index(3), e.Material[:])
		r.blob(x.Index(4), e.Identity[:])
	}
	return s
}
