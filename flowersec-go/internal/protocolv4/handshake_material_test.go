package protocolv4

import (
	"bytes"
	"testing"
)

func TestRuntimeHandshakeMaterialUsesOriginalCredentials(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	fsa := runtimeFSA(t, f, false, f.serverCertificate)
	m, err := f.hello.BindHandshakeMaterial(f.artifact, f.binding, f.certificate, f.serverCertificate, f.fsb, fsa)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	psk, _ := f.artifact.Field("e2ee_psk").ByteString()
	expectedPSK := [32]byte(psk)
	clientKey, _ := f.certificate.Field("ed25519_public_key").ByteString()
	serverKey, _ := f.serverCertificate.Field("noise_static_public_key").Named("NoiseStaticPublicKey", "public_key_bytes").ByteString()
	expectedEd := [32]byte(clientKey)
	expectedDH := bytes.Clone(serverKey)
	fsb, _ := f.fsb.Bytes()
	fsaBytes, _ := fsa.Bytes()
	expectedFSB, expectedFSA := bytes.Clone(fsb), bytes.Clone(fsaBytes)
	clientExpiry, _ := f.certificate.Field("expires_at_ms").Uint()
	serverExpiry, _ := f.serverCertificate.Field("expires_at_ms").Uint()
	_, sessionEnd := f.binding.Deadlines()
	idle, _ := f.artifact.Field("session_contract").Named("SessionContract", "idle_duration_ms").Uint()
	for _, source := range []*SignedMap{f.artifact, f.certificate, f.serverCertificate, f.fsb, fsa} {
		source.Release()
	}
	first, second := make([]byte, 65536), make([]byte, 16384)
	facts, n, k, err := m.Read(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if facts.PSK != expectedPSK || facts.Client.EdPublic != expectedEd || !bytes.Equal(facts.Server.DHPublic[:facts.Server.DHBytes], expectedDH) {
		t.Fatal("credential key projection changed")
	}
	if facts.Profile != f.binding.profile || facts.Session.Contract.Limits().ApplicationProfile != "transport" || facts.Features != f.hello.features || facts.Session.Contract.Limits().IdleDurationMS != idle {
		t.Fatal("signed contract not preserved", facts.Profile, facts.Session.Contract.Limits().ApplicationProfile, facts.Features, facts.Session.Contract.Limits().IdleDurationMS)
	}
	if facts.SessionNotAfterMS != min(clientExpiry, serverExpiry, sessionEnd) {
		t.Fatal("original hard deadline widened")
	}
	if !bytes.Equal(first[:n], expectedFSB) || !bytes.Equal(second[:k], expectedFSA) {
		t.Fatal("original admission maps changed")
	}
	clear(first)
	clear(second)
	clear(facts.PSK[:])
	facts.Client.EdPublic[0] ^= 1
	again, _, _, err := m.Read(first, second)
	if err != nil || again.PSK != expectedPSK || again.Client.EdPublic != expectedEd {
		t.Fatal("caller changed retained original", err)
	}
	m.Close()
	if closed, _, _, err := m.Read(first, second); err == nil || closed.PSK != ([32]byte{}) {
		t.Fatal("closed material reused")
	}
}

func TestRuntimeHandshakeMaterialRejectsSubstitutionAndRejection(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	fsa := runtimeFSA(t, f, false, f.serverCertificate)
	wrong := f.mutate(t, f.artifact, "Artifact", func(root *cborRefValue) {
		v := oracleField(t, f.r.cborReference, "Artifact", root, "e2ee_psk")
		v.data = bytes.Clone(v.data)
		v.data[0] ^= 1
	})
	if m, err := f.hello.BindHandshakeMaterial(wrong, f.binding, f.certificate, f.serverCertificate, f.fsb, fsa); err == nil || m != nil {
		t.Fatal("different signed PSK used")
	}
	rejected := runtimeFSA(t, f, true, f.serverCertificate)
	if m, err := f.hello.BindHandshakeMaterial(f.artifact, f.binding, f.certificate, f.serverCertificate, f.fsb, rejected); err != CBORFailure("handshake_rejected") || m != nil {
		t.Fatal("rejection created material", err)
	}
	if m, err := f.hello.BindHandshakeMaterial(f.artifact, f.binding, f.serverCertificate, f.certificate, f.fsb, fsa); err == nil || m != nil {
		t.Fatal("reversed identity keys used")
	}
}
