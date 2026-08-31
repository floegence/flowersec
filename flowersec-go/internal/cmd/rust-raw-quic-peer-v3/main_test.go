package main

import (
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
)

func TestInteropContractIsValidAndStable(t *testing.T) {
	contract := interopContract()
	if contract.MaxInboundStreams != interopMaxStreams || contract.InitExpireAtUnixSeconds <= time.Now().Unix() {
		t.Fatalf("invalid interop contract: %+v", contract)
	}
	hash, _, err := artifactv3.ComputeSessionContractHash(contract)
	if err != nil {
		t.Fatalf("ComputeSessionContractHash: %v", err)
	}
	if hash != contract.ContractHash {
		t.Fatalf("contract hash = %x, want %x", contract.ContractHash, hash)
	}
}

func TestInteropArtifactsBindCAAndV3WireProfile(t *testing.T) {
	for _, profile := range []string{"direct", "tunnel"} {
		artifact := interopArtifact(profile, "127.0.0.1:4443")
		if err := artifactv3.ValidateArtifact(artifact); err != nil {
			t.Fatalf("ValidateArtifact(%s): %v", profile, err)
		}
		candidate := artifact.Path.Candidates[0]
		if candidate.TLS.Mode != artifactv3.TLSModeCA || len(candidate.TLS.Pins) != 0 {
			t.Fatalf("%s TLS policy = %+v", profile, candidate.TLS)
		}
		request, err := artifactv3.BuildRequest(artifact, candidate.ID)
		if err != nil {
			t.Fatalf("BuildRequest(%s): %v", profile, err)
		}
		raw, err := artifactv3.MarshalRequest(request)
		if err != nil {
			t.Fatalf("MarshalRequest(%s): %v", profile, err)
		}
		decoded, err := artifactv3.ParseRequest(raw)
		if err != nil {
			t.Fatalf("ParseRequest(%s): %v", profile, err)
		}
		if err := validateAdmission(profile, decoded); err != nil {
			t.Fatalf("validateAdmission(%s): %v", profile, err)
		}
	}
}
