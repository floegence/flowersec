package protocolv2_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

func TestEpochAndStreamKDFVector(t *testing.T) {
	sessionPRK := array32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	h3 := array32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

	roots, err := protocolv2.DeriveEpochZero(sessionPRK, protocolv2.DirectionClientToServer)
	if err != nil {
		t.Fatalf("DeriveEpochZero: %v", err)
	}
	assertHex(t, "epoch secret", roots.EpochSecret[:], "a52cb54b28e786cbb4a24e0f5b7f905302de0ba28e1972614df91551859fcbd7")
	assertHex(t, "control root", roots.ControlRoot[:], "7e2b0d872a14fd45cbcaaaa4e5fcd54614dd9469a74234d78d231d3892b304fb")
	assertHex(t, "stream root", roots.StreamRoot[:], "759b2af150f4d2973aa1c6498c08a7b1a901b485878732b964f73b1dd11951db")
	assertHex(t, "setup root", roots.SetupMACRoot[:], "5375c7c0cdcf613ee6a5f7d447b15cbd26f1d119936e81564a2924083dd688fc")
	assertHex(t, "rekey root", roots.RekeyRoot[:], "8f7b3eac77e7bbd1e9de7cafac1454a2c7ced9177ca6aa3d8d441b9302ad1f73")

	material, err := protocolv2.DeriveStreamMaterial(roots.StreamRoot, h3, 1, protocolv2.DirectionClientToServer, 0)
	if err != nil {
		t.Fatalf("DeriveStreamMaterial: %v", err)
	}
	assertHex(t, "stream secret", material.Secret[:], "74346dbabdbe4a26eaa3b8f131d868450bab313b3ef8f5e68429f0c9a52b431d")
	assertHex(t, "record key", material.RecordKey[:], "c5280301fb2a51041ba95ee6c9806628e37e3b2668515252bc81a68e8e8ad675")
	assertHex(t, "nonce prefix", material.NoncePrefix[:], "2ffc7497")
}

func TestSetupMACAndChaChaRecordVector(t *testing.T) {
	h3 := array32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	setupRoot := array32(t, "5375c7c0cdcf613ee6a5f7d447b15cbd26f1d119936e81564a2924083dd688fc")
	key := array32(t, "c5280301fb2a51041ba95ee6c9806628e37e3b2668515252bc81a68e8e8ad675")
	noncePrefix := array4(t, "2ffc7497")

	preface := protocolv2.SetupPreface{OpenerRole: protocolv2.RoleClient, LogicalStreamID: 1}
	mac, err := protocolv2.ComputeSetupMAC(setupRoot, h3, preface)
	if err != nil {
		t.Fatalf("ComputeSetupMAC: %v", err)
	}
	preface.SetupMAC = mac
	rawPreface, err := preface.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	assertHex(t, "FSS2", rawPreface, "465353320201000000000000000000010000000000000000c27da2a7d534bed76081ad15953cb1e88b9571437144cd95da397a3f07429e18")

	inner, err := protocolv2.MarshalInnerRecord(protocolv2.InnerData, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	header := protocolv2.RecordHeader{Epoch: 0, Sequence: 0, CiphertextLength: uint32(len(inner) + protocolv2.AEADTagBytes)}
	ciphertext, err := protocolv2.SealRecord(protocolv2.SuiteChaCha20Poly1305, key, noncePrefix, h3, 1, protocolv2.DirectionClientToServer, header, inner)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	assertHex(t, "ciphertext", ciphertext, "dde71c528b5d57dff82ade61755221e0ef56e80efc750e1023c20f")
	aesCiphertext, err := protocolv2.SealRecord(protocolv2.SuiteAES256GCM, key, noncePrefix, h3, 1, protocolv2.DirectionClientToServer, header, inner)
	if err != nil {
		t.Fatalf("SealRecord(AES): %v", err)
	}
	assertHex(t, "AES ciphertext", aesCiphertext, "3f2c55ae2b28e78821e2c88e03d1ccf56f068de41e5d27ec9b2ea8")

	plaintext, err := protocolv2.OpenRecord(protocolv2.SuiteChaCha20Poly1305, key, noncePrefix, h3, 1, protocolv2.DirectionClientToServer, header, ciphertext)
	if err != nil {
		t.Fatalf("OpenRecord: %v", err)
	}
	if !bytes.Equal(plaintext, inner) {
		t.Fatalf("plaintext = %x, want %x", plaintext, inner)
	}
	if !protocolv2.VerifySetupMAC(setupRoot, h3, preface) {
		t.Fatal("valid setup MAC rejected")
	}
	preface.SetupMAC[0] ^= 1
	if protocolv2.VerifySetupMAC(setupRoot, h3, preface) {
		t.Fatal("tampered setup MAC accepted")
	}
}

func TestRecordAuthenticationBindsStreamDirectionSequenceAndHeader(t *testing.T) {
	h3 := array32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	key := array32(t, "c5280301fb2a51041ba95ee6c9806628e37e3b2668515252bc81a68e8e8ad675")
	noncePrefix := array4(t, "2ffc7497")
	inner, err := protocolv2.MarshalInnerRecord(protocolv2.InnerData, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	header := protocolv2.RecordHeader{CiphertextLength: uint32(len(inner) + protocolv2.AEADTagBytes)}
	ciphertext, err := protocolv2.SealRecord(protocolv2.SuiteChaCha20Poly1305, key, noncePrefix, h3, 1, protocolv2.DirectionClientToServer, header, inner)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		streamID  uint64
		direction protocolv2.Direction
		header    protocolv2.RecordHeader
	}{
		{name: "stream relocation", streamID: 3, direction: protocolv2.DirectionClientToServer, header: header},
		{name: "direction swap", streamID: 1, direction: protocolv2.DirectionServerToClient, header: header},
		{name: "sequence replay", streamID: 1, direction: protocolv2.DirectionClientToServer, header: protocolv2.RecordHeader{Sequence: 1, CiphertextLength: header.CiphertextLength}},
		{name: "epoch swap", streamID: 1, direction: protocolv2.DirectionClientToServer, header: protocolv2.RecordHeader{Epoch: 1, CiphertextLength: header.CiphertextLength}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := protocolv2.OpenRecord(protocolv2.SuiteChaCha20Poly1305, key, noncePrefix, h3, tc.streamID, tc.direction, tc.header, ciphertext)
			if !errors.Is(err, protocolv2.ErrAuthentication) {
				t.Fatalf("error = %v, want ErrAuthentication", err)
			}
		})
	}
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	wantBytes, err := hex.DecodeString(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantBytes) {
		t.Fatalf("%s = %x, want %x", name, got, wantBytes)
	}
}

func array32(t *testing.T, value string) [32]byte {
	t.Helper()
	var out [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(out) {
		t.Fatalf("bad 32-byte fixture %q", value)
	}
	copy(out[:], raw)
	return out
}

func array4(t *testing.T, value string) [4]byte {
	t.Helper()
	var out [4]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(out) {
		t.Fatalf("bad 4-byte fixture %q", value)
	}
	copy(out[:], raw)
	return out
}
