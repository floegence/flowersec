package protocolv4

import (
	"encoding/hex"
	"testing"
)

func TestSessionParametersDetachOriginalSignedSpanAndContract(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	p, err := f.artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	wantArtifact, _ := f.artifact.Digest("artifact_digest")
	contract := f.artifact.Field("session_contract")
	wantContract, _ := fullMapDigest("session_contract_digest", "SessionContract", contract.Encoded())
	issued, _ := f.artifact.Field("issued_at_ms").Uint()
	expires, _ := f.artifact.Field("session_not_after_ms").Uint()
	if !p.Contract.Valid() || p.ArtifactDigest != wantArtifact || p.Contract.Digest() != wantContract || p.IssuedAtMS != issued || p.SessionNotAfterMS != expires || p != f.hello.SessionParameters() {
		t.Fatal("original signed parameters changed")
	}
	limits := p.Contract.Limits()
	for field, got := range map[string]uint64{"max_frame": uint64(limits.MaxFrame), "max_streams": uint64(limits.MaxStreams), "max_credit": limits.MaxCredit, "idle_duration_ms": limits.IdleDurationMS} {
		want, _ := contract.Named("SessionContract", field).Uint()
		if got != want {
			t.Fatal(field, got, want)
		}
	}
	f.artifact.Release()
	if _, err := f.artifact.SessionParameters(); err == nil {
		t.Fatal("released Artifact reused")
	}
	limits.MaxFrame = 1
	limits.Rekey.Burst = 0
	if p.Contract.Limits().MaxFrame == 1 || p.Contract.Limits().Rekey.Burst == 0 || p != f.hello.SessionParameters() {
		t.Fatal("view changed retained contract")
	}
}

func TestSessionContractProjectionCoversVariantsAndMaximums(t *testing.T) {
	for _, id := range []string{"session_contract_transport", "session_contract_transport_zero", "session_contract_services", "session_contract_execution", "session_contract_encoding_maximum"} {
		t.Run(id, func(t *testing.T) {
			v := oracleSeed(t, id)
			d, err := NewDecoder(64, 32)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := d.DecodeMap(wire, "SessionContract", DecodeContext{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := doc.SessionContract()
			if err != nil || !c.Valid() {
				t.Fatal(err)
			}
			r := doc.Root().Named("SessionContract", "rekey_envelope")
			burst, _ := r.Named("RekeyEnvelope", "burst_rounds").Uint()
			refill, _ := r.Named("RekeyEnvelope", "refill_period_ms").Uint()
			start, _ := r.Named("RekeyEnvelope", "request_start_budget_ms").Uint()
			k, present := doc.Root().Named("SessionContract", "rpc_max_general_outstanding").Uint()
			if c.Limits().Rekey != (RekeyEnvelope{uint16(burst), uint32(refill), uint32(start)}) || uint64(c.Limits().RPCMaxGeneralOutstanding) != k || present != (c.Limits().ApplicationProfile != "transport") {
				t.Fatal("rekey or RPC envelope changed")
			}
			doc.Release()
			if _, err := doc.SessionContract(); err == nil {
				t.Fatal("released contract document reused")
			}
			if !c.Valid() {
				t.Fatal("detached contract expired with its decoder")
			}
		})
	}
}
