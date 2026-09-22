package cryptov4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// AdmissionKeyConfig supplies only local key capabilities and the original
// tightened timing owners. All on-wire and credential key identities come from
// the independently validated original HandshakeMaterial, never this config.
type AdmissionKeyConfig struct {
	Role                                   protocolv4.Direction
	LocalDH                                StaticDH
	Signer                                 IdentitySigner
	Deadline                               *timev4.Deadline
	Clock                                  *timev4.Clock
	SessionDeadlineMS, LocalIdleDurationMS uint64
	Authorization                          protocolv4.AuthorizationGuard
}

// AdmissionHandshakeConfig copies the bounded original messages into the
// caller's pre-admitted buffers and derives the complete crypto configuration.
// The buffers remain live through NewHandshake/InitialExchange.Authenticate;
// clear the returned PSK after that original use. A zero or wider local Session
// deadline never removes the original Artifact/activation/certificate cap.
func AdmissionHandshakeConfig(material *protocolv4.HandshakeMaterial, local AdmissionKeyConfig, fsb, fsa []byte) (config HandshakeConfig, err error) {
	if material == nil || local.Role > protocolv4.ServerToClient || local.LocalDH == nil || local.Signer == nil || local.Clock == nil || local.Authorization == nil || !local.Deadline.BelongsTo(local.Clock) || local.SessionDeadlineMS == 0 {
		return config, ErrConfiguration
	}
	facts, n, m, err := material.Read(fsb, fsa)
	if err != nil {
		return config, err
	}
	defer clear(facts.PSK[:])
	deadline := min(local.SessionDeadlineMS, facts.SessionNotAfterMS)
	if local.Deadline.Cap() > deadline {
		return config, ErrHandshake
	}
	if err = local.Deadline.Check(); err != nil {
		return config, err
	}
	if err = local.Authorization.Check(); err != nil {
		return config, err
	}
	identity, peer := facts.Client, facts.Server
	if local.Role == protocolv4.ServerToClient {
		identity, peer = peer, identity
	}
	config = HandshakeConfig{Profile: facts.Profile, Session: facts.Session, Role: local.Role, PSK: facts.PSK, FSB: fsb[:n:n], FSA: fsa[:m:m],
		ContextDigest: facts.Context, AdmissionBinding: facts.Admission, LocalCertificateDigest: identity.Digest, PeerCertificateDigest: peer.Digest,
		LocalDHPublic: identity.DHPublic[:identity.DHBytes:identity.DHBytes], PeerDHPublic: peer.DHPublic[:peer.DHBytes:peer.DHBytes], LocalEdPublic: identity.EdPublic, PeerEdPublic: peer.EdPublic,
		LocalDH: local.LocalDH, Signer: local.Signer, Features: facts.Features, Deadline: local.Deadline, Clock: local.Clock, SessionDeadlineMS: deadline, LocalIdleDurationMS: local.LocalIdleDurationMS, Authorization: local.Authorization}
	return config, nil
}

// CheckRecordContract rejects a locally narrowed frame or widened positive
// scope capacity before the original Noise invocation. It does not reserve
// backing or qualify a provider; those belong to the pre-admission plan.
func CheckRecordContract(config Config, contract protocolv4.SessionContract) error {
	limits := contract.Limits()
	if !contract.Valid() || config.MaxFrame != limits.MaxFrame || config.MaxScopes > limits.MaxStreams {
		return ErrConfiguration
	}
	return nil
}
