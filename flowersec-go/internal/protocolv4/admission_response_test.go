package protocolv4

import (
	"bytes"
	"testing"
)

func runtimeFSA(t *testing.T, f *runtimeAdmissionFixture, rejected bool, certificate *SignedMap) *SignedMap {
	t.Helper()
	seed := oracleSeed(t, "fsa_admitted_fields")
	root, _, err := f.r.decode(oracleBytes(t, seed.Hex), "FSA4", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	field := func(name string) *cborRefValue { return oracleField(t, f.r.cborReference, "FSA4", root, name) }
	for _, name := range []string{"route_digest", "hello_transcript_digest", "transport_context_digest"} {
		value, _ := f.fsb.Field(name).ByteString()
		field(name).data = bytes.Clone(value)
	}
	for _, name := range []string{"selected_features", "binding_mode"} {
		field(name).n, _ = f.fsb.Field(name).Uint()
	}
	admission, err := f.binding.MatchFSB(f.fsb, f.certificate)
	if err != nil {
		t.Fatal(err)
	}
	field("admission_binding").data = admission[:]
	field("client_identity_digest").data = f.binding.clientDigest[:]
	field("server_identity_digest").data = f.binding.serverDigest[:]
	if rejected {
		field("status").n, field("code").n, field("server_epoch").n = 1, 1, 0
		for _, name := range []string{"reservation_key", "admission_binding", "transport_context_digest", "client_identity_digest", "server_identity_digest"} {
			field(name).data = make([]byte, 32)
		}
	}
	field("server_certificate").data, err = certificate.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return signRuntimeFixture(t, "FSA4", root.encode(nil), DecodeContext{})
}

func TestRuntimeFSAAdmittedAndRejectedBindings(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	admitted := runtimeFSA(t, f, false, f.serverCertificate)
	result, err := f.hello.MatchFSA(admitted, f.serverCertificate, f.binding, f.fsb, f.certificate)
	if err != nil || !result.Admitted || result.ServerIdentityDigest != f.binding.serverDigest || result.AdmissionBinding == ([32]byte{}) {
		t.Fatal("admitted facts lost", result, err)
	}
	other := f.mutate(t, f.serverCertificate, "IdentityCertificate", func(root *cborRefValue) {
		oracleField(t, f.r.cborReference, "IdentityCertificate", root, "subject_id").data = []byte("trusted-rejection-signer")
	})
	rejected := runtimeFSA(t, f, true, other)
	result, err = f.hello.MatchFSA(rejected, other, nil, nil, nil)
	if err != nil || result.Admitted || result.Code == 0 || result.ServerIdentityDigest != ([32]byte{}) || result.AdmissionBinding != ([32]byte{}) {
		t.Fatal("rejection promoted sentinel or required admitted certificate digest", result, err)
	}
	wrongAdmitted := runtimeFSA(t, f, false, other)
	if _, err := f.hello.MatchFSA(wrongAdmitted, other, f.binding, f.fsb, f.certificate); err != CBORFailure("admission_identity_binding") {
		t.Fatal("rejection-only certificate became admitted identity", err)
	}
}

func TestRuntimeFSARejectsChangedResponseAndSentinels(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	for _, rejected := range []bool{false, true} {
		original := runtimeFSA(t, f, rejected, f.serverCertificate)
		for _, name := range []string{"admission_binding", "transport_context_digest", "route_digest", "hello_transcript_digest", "client_identity_digest", "server_identity_digest", "reservation_key"} {
			if !rejected && name == "reservation_key" {
				continue
			} // Chosen by the original server admission CAS.
			t.Run(name, func(t *testing.T) {
				wrong := f.mutate(t, original, "FSA4", func(root *cborRefValue) {
					v := oracleField(t, f.r.cborReference, "FSA4", root, name)
					v.data = bytes.Clone(v.data)
					v.data[0] ^= 1
				})
				if _, err := f.hello.MatchFSA(wrong, f.serverCertificate, f.binding, f.fsb, f.certificate); err == nil {
					t.Fatal("different signed response accepted", rejected)
				}
			})
		}
	}
}
