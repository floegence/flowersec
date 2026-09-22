package protocolv4

import "unsafe"

// FeatureEnvelopePolicy is trusted local composition before sending the
// proposed local hello offer. LocalCapabilities describes the actual local
// feature implementation; RouteAllowedFeatures is the already checked whole
// route/provider/grant policy used by HelloPolicy. Neither value comes from an
// unauthenticated peer. No assumed remote capability narrows this envelope.
type FeatureEnvelopePolicy struct {
	LocalCapabilities, ProposedOffer, RouteAllowedFeatures uint64
}

// FeatureEnvelope is a detached immutable enumeration, not authorization or a
// resource reservation. It covers every successful feature intersection that
// any peer offer can produce from this original Artifact/candidate/local offer.
// Its current canonical registry has two features and at most four selections;
// registry growth requires an explicit implementation/capacity update.
//
// For each Selection, composition must first compute its complete owner-union
// vector, then take the dimensionwise maximum across selections. This helper
// proves neither feature_min registration nor the complete ready_min bound.
type FeatureEnvelope struct {
	session     ArtifactSessionParameters
	index       uint64
	candidateID [16]byte
	policy      FeatureEnvelopePolicy
	selections  [4]uint64
	count       uint8
}

// FeatureEnvelopeBackingBytes is its retained value storage. The original
// Artifact codec and shared generated registries keep their existing charges.
func FeatureEnvelopeBackingBytes() uint64 { return uint64(unsafe.Sizeof(FeatureEnvelope{})) }

func (e FeatureEnvelope) Len() int { return int(e.count) }
func (e FeatureEnvelope) Selection(index int) (uint64, bool) {
	if index < 0 || index >= int(e.count) {
		return 0, false
	}
	return e.selections[index], true
}
func (e FeatureEnvelope) SessionParameters() ArtifactSessionParameters { return e.session }
func (e FeatureEnvelope) CandidateIndex() uint64                       { return e.index }
func (e FeatureEnvelope) Policy() FeatureEnvelopePolicy                { return e.policy }

// MatchCandidate checks the original index and candidate ID before spend. An
// envelope does not retain the route digest: HelloBinding.MatchOriginal is the
// final complete route gate, and this comparison confers no route authority.
func (e FeatureEnvelope) MatchCandidate(member PoolMember) error {
	if e.count == 0 || !e.session.Contract.Valid() || e.index != member.Index || e.candidateID != member.CandidateID {
		return CBORFailure("hello_feature_selection")
	}
	return nil
}

// FeatureEnvelope uses the same Artifact/profile rules and feature selector as
// authenticated hello negotiation. Unknown optional signed/offer bits remain
// ignored exactly as there; unknown required bits make every result impossible.
// Known proposed bits must fit the actual local capability. No offer is silently
// reduced, and required obligations cannot be deferred until after spend.
func (m *SignedMap) FeatureEnvelope(index uint64, policy FeatureEnvelopePolicy) (FeatureEnvelope, error) {
	var result FeatureEnvelope
	if m == nil || m.codec == nil || m.codec.schema != "Artifact" {
		return result, CBORFailure("artifact_owner")
	}
	m.codec.mu.Lock()
	defer m.codec.mu.Unlock()
	if m.codec.current != m {
		return result, CBORFailure("artifact_owner")
	}
	r, err := runtimeHello()
	if err != nil {
		return result, err
	}
	rules, err := runtimeRules()
	if err != nil {
		return result, err
	}
	// The selector has explicit semantics for these current registry entries.
	// A new registered feature must not acquire guessed dependency semantics.
	if len(rules.Fields["feature_registry"]) != 2 || r.datagram == r.resume || r.known != r.datagram|r.resume {
		return result, CBORFailure("registry_unresolved")
	}
	if policy.LocalCapabilities & ^r.known != 0 || policy.ProposedOffer&r.known & ^policy.LocalCapabilities != 0 {
		return result, CBORFailure("configuration_capacity")
	}
	if policy.RouteAllowedFeatures & ^r.known != 0 {
		return result, CBORFailure("hello_route_features")
	}
	session, err := m.sessionParametersLocked()
	if err != nil {
		return result, err
	}
	profiles, err := loadRecordRegistry()
	if err != nil {
		return result, err
	}
	if _, ok := profiles.Profiles[session.Profile]; !ok {
		return result, ErrRecordProfile
	}
	// Keep the canonical shared registry string instead of retaining another
	// dynamically decoded profile copy beyond this synchronous projection.
	for profile := range profiles.Profiles {
		if profile == session.Profile {
			session.Profile = profile
			break
		}
	}
	root := m.document.Root()
	candidates := root.Named("Artifact", "candidates")
	if index >= uint64(candidates.Len()) {
		return result, CBORFailure("pool_index_membership")
	}
	candidate := candidates.Index(int(index))
	helloPolicy := HelloPolicy{RouteAllowedFeatures: policy.RouteAllowedFeatures}
	ceiling, _, _, err := selectHelloFeatures(root, candidate, policy.ProposedOffer, r.known, helloPolicy)
	if err != nil {
		return result, err
	}
	result.session, result.index, result.policy = session, index, policy
	id, _ := candidate.Named("Candidate", "candidate_id").ByteString()
	copy(result.candidateID[:], id)
	// A peer can offer any subset of the effective ceiling. Invoke the same
	// selector for each; impossible required-feature subsets are excluded.
	for peer := ceiling; ; peer = (peer - 1) & ceiling {
		selected, _, _, err := selectHelloFeatures(root, candidate, policy.ProposedOffer, peer, helloPolicy)
		if err != nil && err != CBORFailure("hello_required_features") {
			return FeatureEnvelope{}, err
		}
		if err == nil {
			duplicate := false
			for i := 0; i < int(result.count); i++ {
				duplicate = duplicate || result.selections[i] == selected
			}
			if !duplicate {
				if int(result.count) == len(result.selections) {
					return FeatureEnvelope{}, CBORFailure("configuration_capacity")
				}
				position := int(result.count)
				for position > 0 && result.selections[position-1] > selected {
					result.selections[position] = result.selections[position-1]
					position--
				}
				result.selections[position] = selected
				result.count++
			}
		}
		if peer == 0 {
			break
		}
	}
	if result.count == 0 {
		return FeatureEnvelope{}, CBORFailure("hello_required_features")
	}
	return result, nil
}

// MatchHello checks the authenticated selection, exact original local offer,
// trusted route feature policy, and original Artifact/candidate against this
// already preadmitted envelope. role names the local endpoint: ClientToServer
// checks ClientHello.offered_features; ServerToClient checks the server offer.
// Unknown optional offer bits must also match even when selection is unchanged.
// The original Connect owner still binds the attempt and actual carrier; these
// immutable feature facts cannot establish trust or connection authority.
func (e FeatureEnvelope) MatchHello(h *HelloBinding, role Direction) error {
	if e.count == 0 || h == nil || h.artifact != e.session.ArtifactDigest || h.winner.Index != e.index || h.winner.CandidateID != e.candidateID {
		return CBORFailure("hello_feature_selection")
	}
	if role > ServerToClient || h.offers[role] != e.policy.ProposedOffer || h.routeAllowedFeatures != e.policy.RouteAllowedFeatures {
		return CBORFailure("hello_feature_selection")
	}
	for i := 0; i < int(e.count); i++ {
		if e.selections[i] == h.features {
			return nil
		}
	}
	return CBORFailure("hello_feature_selection")
}
