package sessionv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// hopAuthentication is part of the original establishment reservation. It
// borrows that owner's verified maps and signer until the initial exchange
// retires. HELLO challenges belong to the actual prepared carrier, so a second
// connection cannot reuse this context even if its signed route is identical.
type hopAuthentication struct {
	grant, localCertificate, relayCertificate *protocolv4.SignedMap
	signer                                    cryptov4.IdentitySigner
	localKey, relayKey                        [32]byte
	incarnation                               [16]byte
	challenge                                 [32]byte
	context                                   protocolv4.HopChallengeContext
	possession                                protocolv4.GrantPossessionInput
	contextBytes                              [129]byte
	role                                      uint8
	dialer                                    bool
	relay                                     bool
}

func hopAuthenticationScratchBytes() (uint64, error) {
	// The closure verifies the exact role subset; possession helpers have one
	// bounded challenge decoder and signing message alive at a time. Transport
	// framing/HELLO/proof decoding reuse the existing initial workspaces.
	closure, err := protocolv4.EndpointCredentialsBackingBytes()
	if err != nil {
		return 0, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(129, 128)
	return closure + decoder + 1024, err
}

// prepareHop runs before durable spend with the admission gate held. No
// credential is sent here, and no signer or network provider is called.
func (p *SessionEstablishment) prepareHop(a *SessionAdmissionReservation) error {
	if p.material.Grant == nil {
		return nil
	}
	if a.accepted != nil {
		return a.accepted.matchTunnelMaterial(&p.material, p.expected)
	}
	if err := p.hop.prepare(&p.material, p.expected, a.prepared, a.config.Initial.Limits); err != nil {
		return err
	}
	a.config.Initial.hop = &p.hop
	return nil
}

func (h *hopAuthentication) prepare(m *EstablishmentMaterial, selected protocolv4.PoolMember, prepared *PreparedCarrier, limits InitialLimits) error {
	closure, err := protocolv4.BindEndpointCredentials(m.Role, m.Artifact, selected.Index, m.ClientCertificate, m.ServerCertificate, m.Grant, m.RelayCertificate)
	if err != nil {
		return err
	}
	if m.Authority != nil {
		if err = closure.MatchActivation(m.Authority); err != nil {
			return err
		}
	}
	name := "client_leg"
	local := m.ClientCertificate
	if m.Role == protocolv4.ServerToClient {
		name, local = "server_leg", m.ServerCertificate
	}
	leg := m.Artifact.Field("candidates").Index(int(selected.Index)).Named("Candidate", name)
	dialer, dialerOK := leg.Named("Leg", "dialer_role").Uint()
	listener, listenerOK := leg.Named("Leg", "listener_role").Uint()
	legID, legOK := leg.Named("Leg", "leg_id").ByteString()
	pairing, pairOK := m.Grant.Field("pairing_id").ByteString()
	localKey, localOK := local.Field("ed25519_public_key").ByteString()
	relayKey, relayOK := m.RelayCertificate.Field("ed25519_public_key").ByteString()
	role := uint64(m.Role)
	if !dialerOK || !listenerOK || !(dialer == role && listener == 2 || dialer == 2 && listener == role) || !legOK || len(legID) != 16 || !pairOK || len(pairing) != 16 || !localOK || len(localKey) != 32 || !relayOK || len(relayKey) != 32 {
		return protocolv4.ErrHopAuthContext
	}
	digest, err := m.Grant.Digest("grant_digest")
	if err != nil {
		return err
	}
	maximum, err := protocolv4.SchemaByteLimit("HOP_AUTH_HELLO")
	if err != nil {
		return err
	}
	if limits.MaxFrame < maximum {
		return cryptov4.ErrCapacity
	}
	prepared.mu.Lock()
	incarnation, challenge := prepared.incarnation, prepared.hopChallenge
	prepared.mu.Unlock()
	if incarnation == ([16]byte{}) || challenge == ([32]byte{}) {
		return protocolv4.ErrHopAuthContext
	}
	*h = hopAuthentication{grant: m.Grant, localCertificate: local, relayCertificate: m.RelayCertificate, signer: m.Signer,
		localKey: [32]byte(localKey), relayKey: [32]byte(relayKey), incarnation: incarnation, challenge: challenge, role: uint8(role), dialer: dialer == role,
		context:    protocolv4.HopChallengeContext{LegID: [16]byte(legID), DialerRole: uint8(dialer), ListenerRole: uint8(listener)},
		possession: protocolv4.GrantPossessionInput{GrantDigest: digest, RouteDigest: selected.RouteDigest, LegID: [16]byte(legID), PairingID: [16]byte(pairing), Role: uint8(role)}}
	if h.dialer {
		h.context.DialerIncarnation, h.context.DialerChallenge = incarnation, challenge
	} else {
		h.context.ListenerIncarnation, h.context.ListenerChallenge = incarnation, challenge
	}
	return nil
}

func (h *hopAuthentication) flight(index uint8) (protocolv4.HopAuthPhase, protocolv4.HopSenderRole, bool) {
	switch index {
	case 0, 1:
		send := (index == 0) == h.dialer
		role := protocolv4.HopSenderRelay
		if send != h.relay {
			role = protocolv4.HopSenderEndpoint
		}
		return protocolv4.HopAuthHelloPhase, role, send
	case 2:
		return protocolv4.HopAuthEndpointProofPhase, protocolv4.HopSenderEndpoint, !h.relay
	default:
		return protocolv4.HopAuthRelayProofPhase, protocolv4.HopSenderRelay, h.relay
	}
}

func (h *hopAuthentication) hello(dst []byte) (int, error) {
	certificate, err := h.localCertificate.Bytes()
	if err != nil {
		return 0, err
	}
	fields := []protocolv4.Field{{Name: "phase", Number: 0},
		{Name: "local_incarnation", Kind: protocolv4.ByteString, Bytes: h.incarnation[:]},
		{Name: "local_challenge", Kind: protocolv4.ByteString, Bytes: h.challenge[:]},
		{Name: "identity_certificate", Kind: protocolv4.ByteString, Bytes: certificate}}
	if !h.relay {
		grant, err := h.grant.Bytes()
		if err != nil {
			return 0, err
		}
		fields = append(fields, protocolv4.Field{Name: "grant", Kind: protocolv4.ByteString, Bytes: grant})
	}
	wire, err := protocolv4.EncodeMap(dst, "HOP_AUTH_HELLO", fields)
	return len(wire), err
}

func (h *hopAuthentication) receiveHello(decoder *protocolv4.Decoder, wire []byte) error {
	role := "relay"
	if h.relay {
		role = "endpoint"
	}
	doc, err := decoder.DecodeMap(wire, "HOP_AUTH_HELLO", protocolv4.DecodeContext{Selectors: map[string]string{"hop_sender_role": role}})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	if h.relay {
		grant, _ := root.Named("HOP_AUTH_HELLO", "grant").ByteString()
		expected, err := h.grant.Bytes()
		if err != nil {
			return err
		}
		if !bytes.Equal(grant, expected) {
			return protocolv4.ErrHopAuthContext
		}
	}
	certificate, _ := root.Named("HOP_AUTH_HELLO", "identity_certificate").ByteString()
	expected, err := h.relayCertificate.Bytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(certificate, expected) {
		return protocolv4.ErrHopAuthContext
	}
	incarnation, _ := root.Named("HOP_AUTH_HELLO", "local_incarnation").ByteString()
	challenge, _ := root.Named("HOP_AUTH_HELLO", "local_challenge").ByteString()
	if len(incarnation) != 16 || len(challenge) != 32 {
		return protocolv4.ErrHopAuthContext
	}
	if h.dialer {
		h.context.ListenerIncarnation, h.context.ListenerChallenge = [16]byte(incarnation), [32]byte(challenge)
	} else {
		h.context.DialerIncarnation, h.context.DialerChallenge = [16]byte(incarnation), [32]byte(challenge)
	}
	encoded, err := protocolv4.EncodeHopChallengeContext(h.contextBytes[:], h.context)
	if err != nil || len(encoded) != len(h.contextBytes) {
		return protocolv4.ErrHopAuthContext
	}
	h.possession.HopContext = h.contextBytes[:]
	return nil
}

// authenticateHop is the only path allowed to advance HOP_AUTH. It reuses the
// original initial I/O and watchdog, retains signer tails until return, and
// keeps NEGOTIATE closed until the exact relay possession proof verifies.
func (x *InitialExchange) authenticateHop() (err error) {
	x.mu.Lock()
	if x.config.hop == nil {
		x.mu.Unlock()
		return nil
	}
	if err = x.checkLocked(); err != nil {
		x.mu.Unlock()
		return err
	}
	if x.phase != 0 || x.hopPhase != 0 || x.authenticating || x.sending || x.receiving {
		x.mu.Unlock()
		return ErrInitialPhase
	}
	x.authenticating = true
	h := x.config.hop
	x.mu.Unlock()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		x.mu.Lock()
		defer x.mu.Unlock()
		x.authenticating = false
		if err != nil {
			x.failLocked(err)
		}
		x.cleanupLocked()
	}()
	for flight := uint8(0); flight < 4 && err == nil; flight++ {
		phase, _, send := h.flight(flight)
		if phase == protocolv4.HopAuthHelloPhase {
			if send {
				_, err = x.sendFlight(protocolv4.FrameHopAuth, h.hello, nil, true)
			} else {
				err = x.receiveFlight(protocolv4.FrameHopAuth, func(wire []byte) error { return h.receiveHello(x.receiveDecoder, wire) }, true)
			}
		} else if send {
			_, err = x.sendFlight(protocolv4.FrameHopAuth, func(dst []byte) (int, error) {
				message, err := protocolv4.GrantPossessionMessage(h.possession)
				if err != nil {
					return 0, err
				}
				defer clear(message)
				if err = x.check(); err != nil {
					return 0, err
				}
				proof, err := h.signer.Sign(message)
				if err != nil {
					return 0, err
				}
				if !protocolv4.VerifyEd25519(proof, message, h.localKey[:]) {
					return 0, protocolv4.ErrHopAuthProof
				}
				encoded, err := protocolv4.EncodeHopAuthProof(dst, protocolv4.HopAuthProof{Phase: phase, Proof: [64]byte(proof)})
				return len(encoded), err
			}, nil, true)
		} else {
			err = x.receiveFlight(protocolv4.FrameHopAuth, func(wire []byte) error {
				proof, err := protocolv4.DecodeHopAuthProof(x.receiveDecoder, wire, phase)
				if err != nil {
					return err
				}
				input := h.possession
				input.Role = 2
				return protocolv4.VerifyGrantPossession(input, h.relayKey, proof.Proof)
			}, true)
		}
	}
	returned = true
	return err
}
