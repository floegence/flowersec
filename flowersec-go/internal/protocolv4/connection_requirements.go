package protocolv4

import "errors"

var ErrRequiredGuaranteeUnavailable = errors.New("protocolv4: required guarantee unavailable")
var ErrConnectionRequirementUnavailable = errors.New("protocolv4: connection requirement unavailable")

// CheckProfile compiles an optional exact request against the immutable local
// plan or signed material. It never selects a lower application profile.
func (r V4ConnectionRequirements) CheckProfile(profile string) error {
	if profile != "transport" && profile != "services" && profile != "execution" {
		return ErrConnectionRequirementUnavailable
	}
	if r.ApplicationProfile != nil && string(*r.ApplicationProfile) != profile {
		return ErrConnectionRequirementUnavailable
	}
	return nil
}

// Check uses only original provider/deployment observations. Its caller owns
// their authenticity and complete route binding; an API value is not evidence.
func (r V4ConnectionRequirements) Check(g V4ConnectionGuarantees) error {
	if !g.Valid() || r.IndependentReliableReadProgress && g.ReliableProgress != V4ReliableProgressIndependentWithinProfile ||
		r.BoundStreamInputIsolation && g.BoundStreamInputIsolation != V4BoundStreamInputIsolationBoundStreamWithinProfile ||
		r.Datagram && !g.Datagram || r.LocalConsumerTls13Verification && g.LocalConsumerTls13Verification != V4ConsumerTLS13VerificationConsumerEnforced {
		return ErrRequiredGuaranteeUnavailable
	}
	return nil
}

func (g V4ConnectionGuarantees) Valid() bool {
	if g.ReliableProgress != V4ReliableProgressSharedOrdered && g.ReliableProgress != V4ReliableProgressIndependentWithinProfile ||
		g.BoundStreamInputIsolation != V4BoundStreamInputIsolationSharedFailureScope && g.BoundStreamInputIsolation != V4BoundStreamInputIsolationBoundStreamWithinProfile {
		return false
	}
	switch g.LocalConsumerTls13Verification {
	case V4ConsumerTLS13VerificationNotApplicable, V4ConsumerTLS13VerificationControlledTerminator, V4ConsumerTLS13VerificationConsumerEnforced:
	default:
		return false
	}
	return g.Scope == V4ConnectionGuaranteeScopeCompleteDirectPath && g.Assumptions == V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile ||
		g.Scope == V4ConnectionGuaranteeScopeCompleteRelayPath && g.Assumptions == V4ConnectionGuaranteeAssumptionsTrustedRelayAndPeersWithinTransportProfile
}

// CheckDirectConnectionRequirements is a negative eligibility filter before
// any candidate provider work. Signed configuration cannot establish positive
// provider assurances; the selected original preparation supplies those later.
func (m *SignedMap) CheckDirectConnectionRequirements(index uint64, r V4ConnectionRequirements) error {
	if err := m.CheckDirectListenerCandidate(index); err != nil {
		return err
	}
	session, err := m.SessionParameters()
	if err != nil {
		return err
	}
	if err = r.CheckProfile(session.Contract.Limits().ApplicationProfile); err != nil {
		return err
	}
	leg := m.Field("candidates").Index(int(index)).Named("Candidate", "direct_leg")
	carrier, ok := leg.Named("Leg", "carrier").Uint()
	ws, err := EnumValue("Leg", "carrier", "websocket")
	if err != nil || !ok {
		return CBORFailure("registry_unresolved")
	}
	if carrier == ws && (r.IndependentReliableReadProgress || r.BoundStreamInputIsolation || r.Datagram) {
		return ErrRequiredGuaranteeUnavailable
	}
	access, ok := leg.Named("Leg", "access_class").Uint()
	network, err := EnumValue("Leg", "access_class", "network")
	if err != nil || !ok {
		return CBORFailure("registry_unresolved")
	}
	if r.LocalConsumerTls13Verification && access != network {
		return ErrRequiredGuaranteeUnavailable
	}
	return nil
}

// SelectedDatagram reads the sole feature registry. No guarantee introduces a
// new wire bit, and a possible offer never substitutes for actual selection.
func SelectedDatagram(features uint64) (bool, error) {
	r, err := runtimeHello()
	if err != nil {
		return false, err
	}
	return features&r.datagram != 0, nil
}

// CheckDirectConnectionGuarantees binds provider observations to the signed
// path. In particular a shared WebSocket leg cannot report native isolation,
// independent reliable progress or datagrams, even when no option requests it.
func (m *SignedMap) CheckDirectConnectionGuarantees(index uint64, role Direction, g V4ConnectionGuarantees) error {
	if err := m.CheckDirectListenerCandidate(index); err != nil {
		return err
	}
	if !g.Valid() || g.Scope != V4ConnectionGuaranteeScopeCompleteDirectPath || role > ServerToClient {
		return CBORFailure("carrier_binding_invalid")
	}
	leg := m.Field("candidates").Index(int(index)).Named("Candidate", "direct_leg")
	carrier, _ := leg.Named("Leg", "carrier").Uint()
	ws, err := EnumValue("Leg", "carrier", "websocket")
	if err != nil {
		return err
	}
	if carrier == ws && (g.ReliableProgress != V4ReliableProgressSharedOrdered || g.BoundStreamInputIsolation != V4BoundStreamInputIsolationSharedFailureScope || g.Datagram) {
		return CBORFailure("carrier_binding_invalid")
	}
	access, _ := leg.Named("Leg", "access_class").Uint()
	network, err := EnumValue("Leg", "access_class", "network")
	if err != nil {
		return err
	}
	if role == ServerToClient || access != network {
		if g.LocalConsumerTls13Verification != V4ConsumerTLS13VerificationNotApplicable {
			return CBORFailure("carrier_binding_invalid")
		}
	} else {
		required, ok := leg.Named("Leg", "tls_policy").Named("TLSPolicy", "require_consumer_tls13_verification").Bool()
		if !ok || g.LocalConsumerTls13Verification == V4ConsumerTLS13VerificationNotApplicable || required && g.LocalConsumerTls13Verification != V4ConsumerTLS13VerificationConsumerEnforced {
			return CBORFailure("carrier_binding_invalid")
		}
	}
	return nil
}
