package protocolv4

import (
	"testing"
	"unsafe"
)

func TestRuntimeDecoderPrepaidIDNAIsLazyAndCleared(t *testing.T) {
	vectors := cborRefVectors(t)
	plain, formatted := false, false
	for _, v := range vectors {
		if v.ExpectedError != "" {
			continue
		}
		input := oracleBytes(t, v.Hex)
		d, err := NewDecoder(max(1, len(input)), max(1, len(input)))
		if err != nil {
			t.Fatal(err)
		}
		if d.idna != nil {
			t.Fatal("unused decoder allocated IDNA workspace")
		}
		charge, err := DecoderBackingBytes(max(1, len(input)), max(1, len(input)))
		if err != nil || charge < uint64(unsafe.Sizeof(Decoder{}))+uint64(unsafe.Sizeof(Document{}))+uint64(unsafe.Sizeof(wireIDNAWorkspace{})) {
			t.Fatal("complete deferred workspace is not prepaid", charge, err)
		}
		shape := shapeContext(v.Limits)
		doc, err := d.DecodeMap(input, v.Schema, DecodeContext{Limits: shape.limits, Selectors: shape.selectors})
		if err != nil {
			t.Fatal(v.ID, err)
		}
		if d.idna == nil {
			plain = true
		} else {
			formatted = true
			// Exercise erasure even if this particular format used only ASCII.
			d.idna.work[0], d.idna.scratch[0] = 'x', 'y'
		}
		doc.Release()
		if d.idna != nil {
			for i := range d.idna.work {
				if d.idna.work[i] != 0 || d.idna.scratch[i] != 0 {
					t.Fatal("released decoder retained IDNA scratch", v.ID)
				}
			}
		}
		// A subsequent syntax failure must also erase existing scratch.
		if d.idna != nil {
			d.idna.work[0], d.idna.scratch[0] = 'x', 'y'
		}
		if _, err := d.DecodeShape([]byte{0xff}, "", DecodeContext{}); err == nil {
			t.Fatal("invalid CBOR accepted")
		}
		if d.idna != nil && (d.idna.work[0] != 0 || d.idna.scratch[0] != 0) {
			t.Fatal("failed decoder retained IDNA scratch", v.ID)
		}
		if plain && formatted {
			return
		}
	}
	t.Fatal("corpus did not exercise both unused and required IDNA workspaces", plain, formatted)
}
