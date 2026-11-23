package hkdf

import (
	"bytes"
	stdhkdf "crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestRFC5869SHA256(t *testing.T) {
	decode := func(text string) []byte {
		raw, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	salt := decode("000102030405060708090a0b0c")
	info := decode("f0f1f2f3f4f5f6f7f8f9")
	prk := ExtractSHA256(salt, bytes.Repeat([]byte{0x0b}, 22))
	if !bytes.Equal(prk[:], decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")) {
		t.Fatal("extract differs from RFC 5869 test case 1")
	}
	want := decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got, err := ExpandSHA256(prk, info, len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("expand differs from RFC 5869 test case 1: %v", err)
	}
	var outputs [4][32]byte
	contexts := [][]byte{info, {}, []byte{0}, info}
	var blocks []BlockSHA256
	for index, context := range contexts {
		blocks = append(blocks, BlockSHA256{Info: context, Output: &outputs[index]})
	}
	ExpandBlocksSHA256(prk, blocks...)
	for index, context := range contexts {
		expected, err := stdhkdf.Expand(sha256.New, prk[:], string(context), 32)
		if err != nil || !bytes.Equal(expected, outputs[index][:]) {
			t.Fatalf("independent first block %d: %v", index, err)
		}
	}
	if !bytes.Equal(outputs[0][:], want[:32]) || outputs[0] != outputs[3] {
		t.Fatal("repeated context differs from the published first block")
	}
}

func TestExpandSHA256Lengths(t *testing.T) {
	var prk [32]byte
	for _, size := range []int{0, 1, 4, 31, 32, 33, 64, 65, 255*32 - 1, 255 * 32} {
		got, err := ExpandSHA256(prk, nil, size)
		padded := (size + 31) / 32 * 32
		want, refErr := stdhkdf.Expand(sha256.New, prk[:], "", padded)
		if err != nil || refErr != nil || got == nil || len(got) != size || cap(got) != padded || !bytes.Equal(got[:cap(got)], want) {
			t.Fatalf("expand length %d: %v, reference: %v", size, err, refErr)
		}
	}
	for _, size := range []int{-1, 255*32 + 1} {
		if got, err := ExpandSHA256(prk, nil, size); got != nil || err != errInvalidLength {
			t.Fatalf("invalid length %d: %v", size, err)
		}
	}
}
