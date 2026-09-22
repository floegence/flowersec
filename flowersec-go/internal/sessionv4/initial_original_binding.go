package sessionv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// The original admission installs these immutable facts before the Initial
// watchdog or any I/O starts. They retain no admission-owner backpointer.
type initialOriginalBinding struct {
	enabled    bool
	binding    PreparedCarrierBinding
	features   protocolv4.FeatureEnvelope
	activation *protocolv4.ActivationAuthority
}

func (o initialOriginalBinding) checkProposal(h InitialHello) error {
	if !o.enabled {
		return nil
	}
	session, err := h.Artifact.SessionParameters()
	if err != nil {
		return err
	}
	policy := o.features.Policy()
	if session != o.binding.Session || h.Attempt != o.binding.Attempt || h.Index != o.binding.Candidate.Index || h.Offered != policy.ProposedOffer || h.Policy.RouteAllowedFeatures != policy.RouteAllowedFeatures {
		return protocolv4.CBORFailure("hello_artifact_binding")
	}
	return nil
}

func (o initialOriginalBinding) checkHello(h *protocolv4.HelloBinding) error {
	if !o.enabled {
		return nil
	}
	if err := h.MatchOriginal(o.binding.Session, o.binding.Attempt, o.binding.Candidate); err != nil {
		return err
	}
	return o.features.MatchHello(h, o.binding.Role)
}

// Validate the actual canonical wire before provider publication, including
// low-level Send callers that do not use the negotiation convenience methods.
// Peer offers stay independent; only the original local offer is fixed.
func (o initialOriginalBinding) checkFrame(doc *protocolv4.Document, schema string, role protocolv4.Direction) error {
	if !o.enabled || schema != "ClientHello" && schema != "ServerHello" && schema != "FSB4" {
		return nil
	}
	value := func(name string) protocolv4.Value { return doc.Root().Named(schema, name) }
	if schema == "FSB4" {
		proof, ok := value("activation_authorization").ByteString()
		if !ok {
			return protocolv4.CBORFailure("admission_proof_binding")
		}
		if err := o.activation.MatchProofBytes(proof); err != nil {
			return err
		}
	}
	for _, field := range [...]struct {
		name string
		want []byte
	}{
		{"artifact_digest", o.binding.Session.ArtifactDigest[:]},
		{"candidate_id", o.binding.Candidate.CandidateID[:]},
		{"route_digest", o.binding.Candidate.RouteDigest[:]},
		{"attempt_id", o.binding.Attempt[:]},
	} {
		got, ok := value(field.name).ByteString()
		if !ok || !bytes.Equal(got, field.want) {
			return protocolv4.CBORFailure("hello_artifact_binding")
		}
	}
	if schema == "ClientHello" && role == protocolv4.ClientToServer || schema == "ServerHello" && role == protocolv4.ServerToClient {
		field := "offered_features"
		if schema == "ServerHello" {
			field = "server_offered_features"
		}
		offer, ok := value(field).Uint()
		if !ok || offer != o.features.Policy().ProposedOffer {
			return protocolv4.CBORFailure("hello_feature_selection")
		}
	}
	if schema == "ServerHello" || schema == "FSB4" {
		selected, ok := value("selected_features").Uint()
		if !ok {
			return protocolv4.CBORFailure("hello_feature_selection")
		}
		for i := 0; i < o.features.Len(); i++ {
			if allowed, _ := o.features.Selection(i); selected == allowed {
				return nil
			}
		}
		return protocolv4.CBORFailure("hello_feature_selection")
	}
	return nil
}
