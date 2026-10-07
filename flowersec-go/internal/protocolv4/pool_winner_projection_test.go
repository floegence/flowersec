package protocolv4

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestPoolWinnerControlProjectionCrossLanguageVector(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/interop/pool_winner_projection.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]json.RawMessage
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	text := func(name string) string {
		var value string
		if err := json.Unmarshal(vector[name], &value); err != nil {
			t.Fatal(name, err)
		}
		return value
	}
	number := func(name string) uint64 {
		var value uint64
		if err := json.Unmarshal(vector[name], &value); err != nil {
			t.Fatal(name, err)
		}
		return value
	}
	f := AdmissionFields{Source: "preauthorized_pool", Tenant: text("tenant"), WinnerAuthority: text("winner_authority"), Audience: text("audience"),
		IssuedAt: number("issued_at"), ActivationEnd: number("activation_end"), SessionEnd: number("session_end")}
	for name, dst := range map[string][]byte{"issuer": f.Issuer[:], "lease": f.Lease[:], "artifact": f.Artifact[:], "proof": f.Proof[:],
		"candidate_set": f.CandidateSet[:], "candidate": f.Candidate[:], "route": f.Route[:], "attempt": f.Attempt[:],
		"client_identity": f.ClientIdentity[:], "server_identity": f.ServerIdentity[:]} {
		b, err := hex.DecodeString(text(name))
		if err != nil || len(b) != len(dst) {
			t.Fatal(name, err)
		}
		copy(dst, b)
	}
	var out [8192]byte
	n, err := EncodePoolWinnerControlProjection(out[:], f)
	if err != nil || hex.EncodeToString(out[:n]) != text("hex") {
		t.Fatal("Go/TypeScript projection differs from shared canonical vector", n, err)
	}
	if _, err = EncodePoolWinnerControlProjection(out[:n-1], f); err == nil {
		t.Fatal("short buffer accepted")
	}
	for _, invalid := range []AdmissionFields{
		func() AdmissionFields { v := f; v.Source = "live_authority"; return v }(),
		func() AdmissionFields { v := f; v.CandidateSet = [32]byte{}; return v }(),
		func() AdmissionFields { v := f; v.ActivationEnd = v.IssuedAt; return v }(),
		func() AdmissionFields { v := f; v.WinnerAuthority = ""; return v }(),
	} {
		if _, err = EncodePoolWinnerControlProjection(out[:], invalid); err == nil {
			t.Fatal("invalid pool selection accepted")
		}
	}
}
