package protocolv2

import (
	"bytes"
	"errors"
	"testing"
)

func TestUnreliableFrameRoundTripAndLimits(t *testing.T) {
	header := UnreliableHeader{Epoch: 7, Sequence: 11, ExpiresAtUnixMS: 2_000_000_000_000, CiphertextLength: 19}
	raw, err := header.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != UnreliableHeaderSize || !bytes.Equal(raw[:4], []byte("FSD2")) {
		t.Fatalf("header = %x", raw)
	}
	parsed, err := ParseUnreliableHeader(raw)
	if err != nil || parsed != header {
		t.Fatalf("ParseUnreliableHeader = %+v, %v", parsed, err)
	}

	for _, invalid := range []UnreliableHeader{
		{CiphertextLength: AEADTagBytes - 1},
		{CiphertextLength: MaxUnreliableCiphertextBytes + 1},
	} {
		if _, err := invalid.MarshalBinary(); !errors.Is(err, ErrInvalidUnreliableHeader) {
			t.Fatalf("MarshalBinary(%+v) = %v", invalid, err)
		}
	}
}

func TestUnreliableCryptoIsDomainSeparatedAndAuthenticated(t *testing.T) {
	var epochSecret, h3 [32]byte
	for index := range epochSecret {
		epochSecret[index] = byte(index + 1)
		h3[index] = byte(index + 33)
	}
	material, err := DeriveUnreliableMaterial(epochSecret, h3, DirectionClientToServer, 7)
	if err != nil {
		t.Fatal(err)
	}
	streamRoots, err := DeriveEpochRoots(epochSecret)
	if err != nil {
		t.Fatal(err)
	}
	streamMaterial, err := DeriveStreamMaterial(streamRoots.StreamRoot, h3, 1, DirectionClientToServer, 7)
	if err != nil {
		t.Fatal(err)
	}
	if material.RecordKey == streamMaterial.RecordKey || material.NoncePrefix == streamMaterial.NoncePrefix {
		t.Fatal("unreliable material overlaps reliable stream material")
	}

	header := UnreliableHeader{Epoch: 7, Sequence: 11, ExpiresAtUnixMS: 2_000_000_000_000, CiphertextLength: uint32(len("hello") + AEADTagBytes)}
	ciphertext, err := SealUnreliable(SuiteChaCha20Poly1305, material, h3, DirectionClientToServer, header, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := OpenUnreliable(SuiteChaCha20Poly1305, material, h3, DirectionClientToServer, header, ciphertext)
	if err != nil || string(plaintext) != "hello" {
		t.Fatalf("OpenUnreliable = %q, %v", plaintext, err)
	}
	header.ExpiresAtUnixMS++
	if _, err := OpenUnreliable(SuiteChaCha20Poly1305, material, h3, DirectionClientToServer, header, ciphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered header error = %v", err)
	}
}
