package ledgerv4

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func encodeTopUpRequest(dst []byte, r protocolv4.TopUpRequestFacts) (int, error) {
	w := admissionWriter{dst: dst}
	w.text(r.Tenant)
	for _, v := range [][]byte{r.Source[:], r.Operation[:], r.Pool[:], r.Identity[:], r.Digest[:]} {
		w.bytes(v)
	}
	for _, v := range []uint64{r.Generation, r.DeadlineMS, uint64(r.DesiredCount), uint64(r.MaxItemBytes)} {
		w.uint(v)
	}
	return w.n, w.err
}
func encodeTopUpResponse(dst []byte, f protocolv4.TopUpResponseFacts) (int, error) {
	w := admissionWriter{dst: dst}
	w.text(f.Tenant)
	w.bytes(f.Operation[:])
	w.bytes(f.Source[:])
	w.bytes(f.Digest[:])
	gap := uint64(0)
	if f.Gap {
		gap = 1
	}
	for _, v := range []uint64{f.Generation, f.Highest, f.RetiredThrough, gap, uint64(f.Count)} {
		w.uint(v)
	}
	if f.Count > 4 {
		return 0, ErrStorageFormat
	}
	for _, e := range f.Entries[:f.Count] {
		w.uint(e.Sequence)
		w.uint(e.Generation)
		w.uint(e.ExpiryMS)
		w.bytes(e.Material[:])
		w.bytes(e.Identity[:])
	}
	return w.n, w.err
}

type topUpReader struct {
	data []byte
	n    int
	err  error
}

func (r *topUpReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.data)-r.n {
		r.err = ErrStorageFormat
		return nil
	}
	v := r.data[r.n : r.n+n]
	r.n += n
	return v
}
func (r *topUpReader) uint() uint64 {
	v := r.take(8)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}
func (r *topUpReader) text() string {
	v := r.take(2)
	if len(v) != 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(v))
	if n < 1 || n > 128 {
		r.err = ErrStorageFormat
		return ""
	}
	return string(r.take(n))
}
func (r *topUpReader) done() error {
	if r.err != nil || r.n != len(r.data) {
		return ErrStorageFormat
	}
	return nil
}
func decodeTopUpRequest(wire []byte) (f protocolv4.TopUpRequestFacts, err error) {
	r := topUpReader{data: wire}
	f.Tenant = r.text()
	for _, dst := range [][]byte{f.Source[:], f.Operation[:], f.Pool[:], f.Identity[:], f.Digest[:]} {
		copy(dst, r.take(len(dst)))
	}
	f.Generation = r.uint()
	f.DeadlineMS = r.uint()
	count, size := r.uint(), r.uint()
	if count < 1 || count > 4 || size < 1 || size > 65536 || f.Sequence() == 0 || f.Generation == 0 || f.DeadlineMS == 0 || f.Digest == ([32]byte{}) {
		return f, ErrStorageFormat
	}
	f.DesiredCount = uint32(count)
	f.MaxItemBytes = uint32(size)
	return f, r.done()
}
func decodeTopUpResponse(wire []byte) (f protocolv4.TopUpResponseFacts, err error) {
	r := topUpReader{data: wire}
	f.Tenant = r.text()
	for _, dst := range [][]byte{f.Operation[:], f.Source[:], f.Digest[:]} {
		copy(dst, r.take(len(dst)))
	}
	f.Generation = r.uint()
	f.Highest = r.uint()
	f.RetiredThrough = r.uint()
	gap, count := r.uint(), r.uint()
	if gap > 1 || count < 1 || count > 4 || f.Generation == 0 || f.Digest == ([32]byte{}) {
		return f, ErrStorageFormat
	}
	f.Gap = gap == 1
	f.Count = uint32(count)
	for i := range int(count) {
		e := &f.Entries[i]
		e.Sequence = r.uint()
		e.Generation = r.uint()
		e.ExpiryMS = r.uint()
		copy(e.Material[:], r.take(32))
		copy(e.Identity[:], r.take(32))
		if e.Sequence == 0 || e.Generation != f.Generation || (i > 0 && (f.Entries[i-1].Sequence == math.MaxUint64 || e.Sequence != f.Entries[i-1].Sequence+1)) {
			return f, ErrStorageFormat
		}
	}
	if f.Highest < f.Entries[count-1].Sequence || !f.Gap && f.RetiredThrough != 0 {
		return f, ErrStorageFormat
	}
	return f, r.done()
}
func (j *SQLiteTopUpJournal) readRecovery() (out TopUpRecovery, err error) {
	err = j.store.readOne("SELECT state,CASE WHEN length(binding)=8 THEN binding ELSE NULL END,CASE WHEN length(next_sequence)=8 THEN next_sequence ELSE NULL END,CASE WHEN length(retired_sequence)=8 THEN retired_sequence ELSE NULL END,CASE WHEN length(frontier)=8 THEN frontier ELSE NULL END,CASE WHEN length(pending)<=1024 THEN pending ELSE NULL END,CASE WHEN length(applied)<=1024 THEN applied ELSE NULL END,CASE WHEN length(terminal)<=2048 THEN terminal ELSE NULL END,CASE WHEN length(permanent_fence)=8 THEN permanent_fence ELSE NULL END FROM manifest WHERE id=1", 9, func(v []driver.Value) error {
		state, ok := v[0].(int64)
		if !ok || state < 0 || state > 4 {
			return ErrStorageFormat
		}
		out.State = TopUpJournalState(state)
		for i, dst := range []*uint64{&out.BindingGeneration, &out.NextSequence, &out.RetiredSequence, &out.ArtifactFrontier} {
			*dst, err = readSQLiteUint(v[i+1])
			if err != nil {
				return err
			}
		}
		out.PermanentFenceGeneration, err = readSQLiteUint(v[8])
		if err != nil || out.PermanentFenceGeneration > out.BindingGeneration {
			return ErrStorageFormat
		}
		if out.BindingGeneration == 0 || out.NextSequence == 0 || out.RetiredSequence == math.MaxUint64 {
			return ErrStorageFormat
		}
		pending, pok := v[5].([]byte)
		applied, aok := v[6].([]byte)
		terminal, tok := v[7].([]byte)
		if !pok || !aok || !tok || state != 4 && len(terminal) != 0 {
			return ErrStorageFormat
		}
		if state == 0 {
			if len(pending) != 0 || len(applied) != 0 || out.NextSequence != 1 || out.RetiredSequence != 0 || out.ArtifactFrontier != 0 {
				return ErrStorageFormat
			}
			return nil
		}
		out.Request, err = decodeTopUpRequest(pending)
		if err != nil {
			return err
		}
		r := out.Request
		if r.Tenant != j.config.Tenant || r.Source != j.config.Source || r.Generation > out.BindingGeneration || r.Sequence() == math.MaxUint64 || out.NextSequence != r.Sequence()+1 {
			return ErrStorageFormat
		}
		if state == 4 {
			if len(terminal) == 0 && out.PermanentFenceGeneration != 0 {
				if out.RetiredSequence != r.Sequence() {
					return ErrStorageFormat
				}
				if len(applied) != 0 {
					out.Response, err = decodeTopUpResponse(applied)
					if err != nil || out.Response.Tenant != r.Tenant || out.Response.Source != r.Source || out.Response.Operation != r.Operation || out.Response.Generation != r.Generation || out.Response.Count != r.DesiredCount || out.ArtifactFrontier < out.Response.Entries[out.Response.Count-1].Sequence {
						return ErrStorageFormat
					}
					for _, entry := range out.Response.Entries[:out.Response.Count] {
						if entry.Identity != r.Identity {
							return ErrStorageFormat
						}
					}
				}
				return nil
			}
			out.Terminal, err = decodeTopUpTerminal(terminal, r)
			if err != nil {
				return err
			}
			if out.Terminal.BindingGeneration > out.BindingGeneration || out.Terminal.RetiredSequence != out.RetiredSequence && (out.PermanentFenceGeneration == 0 || out.RetiredSequence != r.Sequence()) {
				return ErrStorageFormat
			}
			if len(applied) != 0 {
				out.Response, err = decodeTopUpResponse(applied)
				if err != nil || out.Response != out.Terminal.Response || out.ArtifactFrontier < out.Response.Entries[out.Response.Count-1].Sequence {
					return ErrStorageFormat
				}
			}
			return nil
		}
		if state == 3 {
			if out.RetiredSequence != r.Sequence() {
				return ErrStorageFormat
			}
		} else if out.RetiredSequence+1 != r.Sequence() {
			return ErrStorageFormat
		}
		if state == 1 {
			if len(applied) != 0 {
				return ErrStorageFormat
			}
			return nil
		}
		out.Response, err = decodeTopUpResponse(applied)
		if err != nil {
			return err
		}
		f := out.Response
		if f.Tenant != r.Tenant || f.Source != r.Source || f.Operation != r.Operation || f.Count != r.DesiredCount || f.Generation != r.Generation || out.ArtifactFrontier < f.Entries[f.Count-1].Sequence {
			return ErrStorageFormat
		}
		for _, e := range f.Entries[:f.Count] {
			if e.Identity != r.Identity {
				return ErrStorageFormat
			}
		}
		return nil
	})
	return out, err
}
func (j *SQLiteTopUpJournal) matchIdentity(certificate, keyReference []byte) error {
	return j.store.readOne("SELECT CASE WHEN length(identity)<=?1 THEN identity ELSE NULL END,CASE WHEN length(key_reference)<=?2 THEN key_reference ELSE NULL END FROM manifest WHERE id=1", 2, func(v []driver.Value) error {
		cert, cok := v[0].([]byte)
		key, kok := v[1].([]byte)
		if !cok || !kok {
			return ErrStorageFormat
		}
		if !bytes.Equal(cert, certificate) || !bytes.Equal(key, keyReference) {
			return ErrConflict
		}
		return nil
	}, named(1, int64(j.config.IdentityBytes)), named(2, int64(j.config.KeyReferenceBytes)))
}
func (j *SQLiteTopUpJournal) poolRecord(material []byte, identity [32]byte) (n int, err error) {
	w := admissionWriter{dst: j.record}
	err = j.store.readOne("SELECT CASE WHEN length(identity)<=?1 THEN identity ELSE NULL END,CASE WHEN length(key_reference)<=?2 THEN key_reference ELSE NULL END FROM manifest WHERE id=1", 2, func(v []driver.Value) error {
		certificate, ok := v[0].([]byte)
		if !ok {
			return ErrStorageFormat
		}
		digest, err := protocolv4.TopUpIdentityDigest(certificate)
		if err != nil || digest != identity {
			return ErrStorageFormat
		}
		for _, value := range v {
			data, ok := value.([]byte)
			if !ok || len(data) == 0 {
				return ErrStorageFormat
			}
			w.uint(uint64(len(data)))
			w.bytes(data)
		}
		return w.err
	}, named(1, int64(j.config.IdentityBytes)), named(2, int64(j.config.KeyReferenceBytes)))
	if err != nil {
		return 0, err
	}
	w.uint(uint64(len(material)))
	w.bytes(material)
	return w.n, w.err
}
