package protocolv4

import "testing"

func TestAdmissionFactsRetainVerifiedOriginalAndRejectSubstitution(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	original, err := f.hello.AdmissionFacts(f.binding, f.fsb, f.certificate)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := original.Fields()
	if err != nil {
		t.Fatal(err)
	}
	if fields.Tenant != f.binding.tenant || fields.Lease != f.binding.lease || fields.Attempt != f.binding.attempt || fields.Proof != f.binding.proofDigest || fields.HelloTranscript != f.hello.transcript || fields.TransportContext != f.hello.transport {
		t.Fatal("original facts lost")
	}
	fields.Lease[0] ^= 1
	fields.Tenant = "replacement"
	again, _ := original.Fields()
	if again.Lease != f.binding.lease || again.Tenant != f.binding.tenant {
		t.Fatal("inspection mutated immutable original")
	}
	if _, err := (AdmissionFacts{}).Fields(); err == nil {
		t.Fatal("zero facts manufactured authorization")
	}
	other := *f.binding
	other.attempt[0] ^= 1
	if _, err := f.hello.AdmissionFacts(&other, f.fsb, f.certificate); err == nil {
		t.Fatal("different attempt accepted")
	}
}
