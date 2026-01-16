package e2ee

import (
	"bytes"
	"testing"
)

func TestEncryptRecordLimits(t *testing.T) {
	var key [32]byte
	var nonce [4]byte
	if _, err := EncryptRecord(key, nonce, RecordFlagApp, 1, make([]byte, 10), 10); err == nil {
		t.Fatalf("expected record too large")
	}
}

func TestDecryptRecordValidations(t *testing.T) {
	var key [32]byte
	var nonce [4]byte
	frame, err := EncryptRecord(key, nonce, RecordFlagApp, 1, []byte("hi"), 1<<20)
	if err != nil {
		t.Fatalf("EncryptRecord failed: %v", err)
	}

	badMagic := append([]byte{}, frame...)
	badMagic[0] = 'X'
	if _, _, _, err := DecryptRecord(key, nonce, badMagic, 1, 1<<20); err == nil {
		t.Fatalf("expected invalid magic")
	}

	badVersion := append([]byte{}, frame...)
	badVersion[4] = ProtocolVersion + 1
	if _, _, _, err := DecryptRecord(key, nonce, badVersion, 1, 1<<20); err == nil {
		t.Fatalf("expected bad version")
	}

	badFlag := append([]byte{}, frame...)
	badFlag[5] = 9
	if _, _, _, err := DecryptRecord(key, nonce, badFlag, 1, 1<<20); err == nil {
		t.Fatalf("expected bad flag")
	}

	if _, _, _, err := DecryptRecord(key, nonce, frame, 2, 1<<20); err == nil {
		t.Fatalf("expected bad seq")
	}

	badLen := append([]byte{}, frame...)
	badLen[14] = 0
	badLen[15] = 0
	badLen[16] = 0
	badLen[17] = 1
	if _, _, _, err := DecryptRecord(key, nonce, badLen, 1, 1<<20); err == nil {
		t.Fatalf("expected invalid length")
	}

	var wrongKey [32]byte
	wrongKey[0] = 9
	if _, _, _, err := DecryptRecord(wrongKey, nonce, frame, 1, 1<<20); err == nil {
		t.Fatalf("expected decrypt failure")
	}
}

func TestDeriveRekeyKeyDeterministic(t *testing.T) {
	var base [32]byte
	var th [32]byte
	for i := range base {
		base[i] = byte(i)
		th[i] = byte(255 - i)
	}
	k1, err := DeriveRekeyKey(base, th, 1, DirC2S)
	if err != nil {
		t.Fatalf("DeriveRekeyKey failed: %v", err)
	}
	k2, err := DeriveRekeyKey(base, th, 1, DirC2S)
	if err != nil {
		t.Fatalf("DeriveRekeyKey failed: %v", err)
	}
	if !bytes.Equal(k1[:], k2[:]) {
		t.Fatalf("expected deterministic output")
	}
	k3, err := DeriveRekeyKey(base, th, 2, DirC2S)
	if err != nil {
		t.Fatalf("DeriveRekeyKey failed: %v", err)
	}
	if bytes.Equal(k1[:], k3[:]) {
		t.Fatalf("expected different output for different seq")
	}
}
