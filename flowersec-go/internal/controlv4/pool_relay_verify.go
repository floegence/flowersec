package controlv4

import (
	"bytes"
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Caller owns the sole factory method position. No secret-bearing map or
// decoder alias escapes this invocation; output contains public projections.
func (f *PoolRelayFactory) verifyMaterial(ctx context.Context, request protocolv4.TopUpRequestFacts, entry protocolv4.TopUpEntryFacts, wire []byte, out []ledgerv4.SQLitePoolRelayParent) (int, error) {
	doc, err := f.material.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return 0, err
	}
	defer doc.Release()
	count, err := protocolv4.CompletePoolRelayParentCount(doc)
	if err != nil {
		return 0, err
	}
	if count > len(out) {
		return 0, resourcev4.ErrCapacity
	}
	root := doc.Root()
	var parts [4][]byte
	for i := range parts {
		var ok bool
		parts[i], ok = root.Index(i).ByteString()
		if !ok || len(parts[i]) == 0 {
			return 0, ErrResponse
		}
	}
	var maps [4]*protocolv4.SignedMap
	defer func() {
		for _, m := range maps {
			if m != nil {
				m.Release()
			}
		}
	}()
	var credentials [3]*protocolv4.Credential
	var common [3]protocolv4.CredentialValidation
	for i, slot := range [3]int{0, 2, 3} {
		maps[slot], err = f.maps[slot].VerifyCredential(parts[slot], f.config.Trust[i])
		if err != nil {
			return 0, err
		}
		credentials[i], err = maps[slot].DetachCredential()
		if err != nil {
			return 0, err
		}
		common[i], err = f.config.Trust[i].ResolveCredential(credentials[i])
		if err != nil {
			return 0, err
		}
	}
	parent := credentials[0]
	scope := parent.Scope()
	if scope.Tenant != request.Tenant || scope.Tenant != f.config.Tenant || scope.Audience != f.config.Audience || scope.Profile != f.config.CryptoProfile || scope.Issuer != f.config.ArtifactIssuer || credentials[1].Facts().Digest != request.Identity || credentials[2].Facts().Digest != f.config.ServerIdentity || entry.ExpiryMS == 0 {
		return 0, ledgerv4.ErrOwner
	}
	for i, c := range credentials {
		if entry.ExpiryMS > c.Scope().ExpiresMS {
			return 0, ledgerv4.ErrOwner
		}
		if _, err = common[i].CheckMaterialCredential(c, scope.ExpiresMS, f.reservation); err != nil {
			return 0, err
		}
	}
	activation, err := f.config.Trust[0].ResolveActivation(parent, f.config.ActivationSigningKeyID, f.delegation[:], f.once[:])
	if err != nil {
		return 0, err
	}
	maps[1], err = f.maps[1].Verify(parts[1], activation.Key, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
	if err != nil {
		return 0, err
	}
	indices := maps[1].Field("candidate_selection").Named("PoolSelectionRef", "candidate_indices")
	if indices.Len() < 1 || indices.Len() > 16 {
		return 0, ErrResponse
	}
	set := root.Index(4)
	matched := 0
	for i := 0; i < indices.Len(); i++ {
		if err = f.check(ctx); err != nil {
			return 0, err
		}
		index, ok := indices.Index(i).Uint()
		if !ok || index >= 16 {
			return 0, ErrResponse
		}
		binding, e := f.selection.BindActivation(maps[0], maps[1], "preauthorized_pool", index)
		if e != nil {
			return 0, e
		}
		if e = binding.MatchCertificates(maps[2], maps[3]); e != nil {
			return 0, e
		}
		end, sessionEnd := binding.Deadlines()
		if entry.ExpiryMS > end {
			return 0, ledgerv4.ErrOwner
		}
		authority, e := activation.Rules.BindActivationAuthority(binding, maps[0], activation.Delegation, activation.Once)
		if e != nil {
			return 0, e
		}
		now, e := f.config.Clock.Sample()
		if e != nil {
			return 0, e
		}
		if e = authority.CheckAdmission(now.Interval); e != nil {
			return 0, e
		}
		if !now.ValidBefore(entry.ExpiryMS) {
			return 0, ledgerv4.ErrOwner
		}
		requirements := common[0].Policy.Requirements()
		if _, e = common[0].Namespace.CheckDetachedActivation(authority, parent, common[0].Issuer, requirements.StalenessMS, requirements.SignerLifetimeMS, sessionEnd); e != nil {
			return 0, e
		}
		path, ok := maps[0].Field("candidates").Index(int(index)).Named("Candidate", "path_kind").Uint()
		if !ok {
			return 0, ErrResponse
		}
		if path != 1 {
			for side := protocolv4.ClientToServer; side <= protocolv4.ServerToClient; side++ {
				closure, e := protocolv4.BindEndpointCredentials(side, maps[0], index, maps[2], maps[3], nil, nil)
				if e != nil {
					return 0, e
				}
				if e = closure.MatchActivation(authority); e != nil {
					return 0, e
				}
				if _, e = closure.CheckCurrent(common[:], sessionEnd); e != nil {
					return 0, e
				}
			}
			continue
		}
		if matched >= count {
			return 0, ErrResponse
		}
		pair := [2]protocolv4.Value{set.Index(matched * 2), set.Index(matched*2 + 1)}
		for _, item := range pair {
			actual, _ := item.Index(0).Uint()
			if actual != index {
				return 0, ErrResponse
			}
		}
		route := f.config.Routes[index]
		if route == nil {
			return 0, resourcev4.ErrConfiguration
		}
		projection, e := f.verifyPair(maps, common, authority, index, sessionEnd, entry.ExpiryMS, pair, *route)
		if e != nil {
			return 0, e
		}
		out[matched] = ledgerv4.SQLitePoolRelayParent{ArtifactSequence: entry.Sequence, Projection: projection, Mapping: route.Mapping, Parent: common[0]}
		matched++
	}
	if matched != count {
		return 0, ErrResponse
	}
	return matched, f.check(ctx)
}

func (f *PoolRelayFactory) verifyPair(maps [4]*protocolv4.SignedMap, common [3]protocolv4.CredentialValidation, activation *protocolv4.ActivationAuthority, index, sessionEnd, expiry uint64, pair [2]protocolv4.Value, route PoolRelayRouteConfig) (*protocolv4.RelayParentProjection, error) {
	var signed [3]*protocolv4.SignedMap
	defer func() {
		for _, m := range signed {
			if m != nil {
				m.Release()
			}
		}
	}()
	var bindings [3]protocolv4.CredentialValidation
	relay, ok := pair[0].Index(3).ByteString()
	other, ok2 := pair[1].Index(3).ByteString()
	if !ok || !ok2 || !bytes.Equal(relay, other) {
		return nil, ErrResponse
	}
	for i := range signed {
		wire, trust := relay, route.RelayTrust
		if i < 2 {
			wire, _ = pair[i].Index(2).ByteString()
			trust = route.Grants[i]
		}
		var err error
		signed[i], err = f.maps[4+i].VerifyCredential(wire, trust)
		if err != nil {
			return nil, err
		}
		credential, err := signed[i].DetachCredential()
		if err != nil {
			return nil, err
		}
		if expiry > credential.Scope().ExpiresMS {
			return nil, ledgerv4.ErrOwner
		}
		bindings[i], err = trust.ResolveCredential(credential)
		if err != nil {
			return nil, err
		}
		if _, err = bindings[i].CheckMaterialCredential(credential, sessionEnd, f.reservation); err != nil {
			return nil, err
		}
	}
	for side := protocolv4.ClientToServer; side <= protocolv4.ServerToClient; side++ {
		closure, err := protocolv4.BindEndpointCredentials(side, maps[0], index, maps[2], maps[3], signed[side], signed[2])
		if err != nil {
			return nil, err
		}
		if err = closure.MatchActivation(activation); err != nil {
			return nil, err
		}
		checks := [5]protocolv4.CredentialValidation{common[0], common[1], common[2], bindings[side], bindings[2]}
		if _, err = closure.CheckCurrent(checks[:], sessionEnd); err != nil {
			return nil, err
		}
	}
	p, err := protocolv4.NewRelayParentProjection(maps[0], activation, maps[2], maps[3], [2]*protocolv4.SignedMap{signed[0], signed[1]}, signed[2])
	if err != nil {
		return nil, err
	}
	if err = p.MatchMapping(route.Mapping); err != nil {
		return nil, err
	}
	return p, nil
}
