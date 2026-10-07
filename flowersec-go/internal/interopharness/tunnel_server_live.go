package interopharness

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func (s *TunnelServer) liveGuard(ctx context.Context) func() error {
	return func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		h := s.Client.Runtime.Authority
		if err := h.Environment.Check(); err != nil {
			return err
		}
		binding, err := s.Registration.Binding()
		if err != nil {
			return err
		}
		now, err := h.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(binding.NotAfterMS) {
			return errors.New("original live B publication expired")
		}
		return nil
	}
}

// verifyOriginalLivePublication uses only the trust/bootstrap owner already
// installed for B. Activation and Grant remain opaque acquisition bytes until
// their original signed maps have been verified. The real allow service then
// verifies the server Grant's complete closure before acknowledging Prepare.
func (s *TunnelServer) verifyOriginalLivePublication(material controlv4.RegisteredLiveServerMaterial) (request sessionv4.TunnelServerAllowRequest, activationDigest, grantDigest [32]byte, err error) {
	h := s.Client.Runtime.Authority
	request, err = s.Registration.Binding()
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	if material.Attempt == ([16]byte{}) || request.Attempt != material.Attempt {
		return request, activationDigest, grantDigest, errors.New("live publication differs from the original B reservation")
	}
	parentCodec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	parent, err := parentCodec.VerifyCredential(s.Client.Material.Artifact, h.Lease.Trust[0])
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	defer parent.Release()
	credential, err := parent.DetachCredential()
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	delegationLimit, err := protocolv4.SchemaByteLimit("ConnectionActivationDelegation")
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	onceLimit, err := protocolv4.SchemaByteLimit("OnceAuthorityRef")
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	resolved, err := h.Lease.Trust[0].ResolveActivation(credential, s.Client.Material.ActivationSigningKeyID, make([]byte, delegationLimit), make([]byte, onceLimit))
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	proofCodec, err := protocolv4.NewSignedMapCodec("ActivationAuthorization", 65536, 4096)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	proof, err := proofCodec.Verify(material.Activation, resolved.Key, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	defer proof.Release()
	selection, err := protocolv4.NewPoolSelectionWorkspace(65536, 65536)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	activation, err := selection.BindActivation(parent, proof, "live_authority", request.Candidate.Index)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	if err = activation.MatchOriginal(h.Admission[1].Core.Session, material.Attempt, request.Candidate); err != nil {
		return request, activationDigest, grantDigest, err
	}
	authority, err := resolved.Rules.BindActivationAuthority(activation, parent, resolved.Delegation, resolved.Once)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	validation, err := h.Lease.Trust[0].ResolveCredential(credential)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	requirements := validation.Policy.Requirements()
	if _, err = validation.Namespace.CheckDetachedActivation(authority, credential, validation.Issuer, requirements.StalenessMS, requirements.SignerLifetimeMS, h.Admission[1].Core.Session.SessionNotAfterMS); err != nil {
		return request, activationDigest, grantDigest, err
	}
	activationDigest, err = proof.Digest("activation_digest")
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	grantCodec, err := protocolv4.NewSignedMapCodec("Grant", 65536, 4096)
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	grant, err := grantCodec.VerifyCredential(material.Grant, h.Lease.Trust[0])
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	defer grant.Release()
	grantDigest, err = grant.Digest("grant_digest")
	if err != nil {
		return request, activationDigest, grantDigest, err
	}
	attempt, ok := grant.Field("attempt_id").ByteString()
	if !ok || len(attempt) != 16 || [16]byte(attempt) != material.Attempt {
		return request, activationDigest, grantDigest, errors.New("original live server Grant differs from its reserved attempt")
	}
	pairing, ok := grant.Field("pairing_id").ByteString()
	if !ok || len(pairing) != 16 {
		return request, activationDigest, grantDigest, errors.New("original live server Grant has no pairing")
	}
	end, ok := grant.Field("not_after_ms").Uint()
	if !ok || end == 0 {
		return request, activationDigest, grantDigest, errors.New("original live server Grant has no deadline")
	}
	activationEnd, _ := activation.Deadlines()
	request.Grant = grantDigest
	request.Pairing = [16]byte(pairing)
	request.NotAfterMS = min(request.NotAfterMS, end, activationEnd)
	err = request.Check()
	return request, activationDigest, grantDigest, err
}
