package e2ee

import (
	"bytes"
	"testing"
)

func FuzzDecodeHandshakeFrame(f *testing.F) {
	f.Add(EncodeHandshakeFrame(HandshakeTypeInit, []byte(`{}`)))
	f.Add([]byte("not a frame"))

	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _, _ = DecodeHandshakeFrame(frame, 8*1024)
	})
}

func FuzzEncryptDecryptRecord_Roundtrip(f *testing.F) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	var noncePre [4]byte
	noncePre[0] = 1
	noncePre[1] = 2
	noncePre[2] = 3
	noncePre[3] = 4

	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0x42}, 1024))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Keep allocations bounded even when the fuzzer generates large inputs.
		if len(plaintext) > 4*1024 {
			plaintext = plaintext[:4*1024]
		}

		const seq = uint64(1)
		frame, err := EncryptRecord(key, noncePre, RecordFlagApp, seq, plaintext, 1<<20)
		if err != nil {
			return
		}
		flags, gotSeq, gotPlain, err := DecryptRecord(key, noncePre, frame, seq, 1<<20)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if flags != RecordFlagApp {
			t.Fatalf("flags mismatch: %v", flags)
		}
		if gotSeq != seq {
			t.Fatalf("seq mismatch: got=%d want=%d", gotSeq, seq)
		}
		if !bytes.Equal(gotPlain, plaintext) {
			t.Fatalf("plaintext mismatch")
		}
	})
}
