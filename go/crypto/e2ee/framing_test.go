package e2ee

import (
	"testing"
)

func TestDecodeHandshakeFrameErrors(t *testing.T) {
	frame := EncodeHandshakeFrame(HandshakeTypeInit, []byte("{}"))

	badMagic := append([]byte{}, frame...)
	badMagic[0] = 'X'
	if _, _, err := DecodeHandshakeFrame(badMagic, 1024); err == nil {
		t.Fatalf("expected bad magic error")
	}

	badVersion := append([]byte{}, frame...)
	badVersion[4] = ProtocolVersion + 1
	if _, _, err := DecodeHandshakeFrame(badVersion, 1024); err == nil {
		t.Fatalf("expected bad version error")
	}

	badLen := append([]byte{}, frame...)
	badLen[6] = 0xff
	badLen[7] = 0xff
	badLen[8] = 0xff
	badLen[9] = 0xff
	if _, _, err := DecodeHandshakeFrame(badLen, 1024); err == nil {
		t.Fatalf("expected invalid length error")
	}

	if _, _, err := DecodeHandshakeFrame(frame, 1); err == nil {
		t.Fatalf("expected payload too large error")
	}
}

func TestLooksLikeRecordFrame(t *testing.T) {
	var key [32]byte
	var nonce [4]byte
	frame, err := EncryptRecord(key, nonce, RecordFlagApp, 1, []byte("hi"), 1<<20)
	if err != nil {
		t.Fatalf("EncryptRecord failed: %v", err)
	}
	if !LooksLikeRecordFrame(frame, 1<<20) {
		t.Fatalf("expected record frame to match")
	}
	if LooksLikeRecordFrame(frame, 1) {
		t.Fatalf("expected record frame to be rejected by maxCiphertext")
	}
}
