package sessionv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

const MaxLeaseTunnelMaterials = 16 * 2

// ArtifactLeaseTunnel is one selected role's original signed material for one
// candidate. Entries are ordered by candidate index, then logical role. An
// endpoint may carry only its own role's complete set; it need not trust or
// receive the other leg's issuer namespace. Supplying both roles is explicit.
type ArtifactLeaseTunnel struct {
	LiveGrant                        *protocolv4.LiveGrantPreparation
	CandidateIndex                   uint64
	Role                             protocolv4.Direction
	Grant, RelayCertificate          *protocolv4.SignedMap
	GrantValidation, RelayValidation protocolv4.CredentialValidation
}

type ArtifactLeaseTunnelBytes struct {
	LiveGrant               *protocolv4.LiveGrantPreparation
	CandidateIndex          uint64
	Role                    protocolv4.Direction
	Grant, RelayCertificate []byte
	GrantTrust, RelayTrust  *protocolv4.NamespaceTrustStore
}

type leaseTunnelMaterial struct {
	liveGrant    protocolv4.LiveGrantPreparation
	pendingGrant bool
	index        uint64
	role         protocolv4.Direction
	maps         [2]*protocolv4.SignedMap
	codecs       [2]*protocolv4.SignedMapCodec
	credentials  [2]*protocolv4.Credential
	validation   [2]protocolv4.CredentialValidation
	bindings     [5]protocolv4.CredentialValidation
}

func (l *ArtifactLease) tunnelMaterial(index uint64, role protocolv4.Direction) *leaseTunnelMaterial {
	for i := 0; i < l.tunnelCount; i++ {
		entry := &l.tunnels[i]
		if entry.index == index && entry.role == role {
			return entry
		}
	}
	return nil
}

func (l *ArtifactLease) installTunnelMaterials(c ArtifactLeaseConfig, trusted *ArtifactLeaseBytesConfig) error {
	count := len(c.Tunnels)
	if trusted != nil {
		count = len(trusted.Tunnels)
	}
	copy(l.allBindings[:3], l.validation[:])
	copy(l.allMaterialCredentials[:3], l.credentials[:])
	if count == 0 && l.maps[4] != nil {
		// Normalize the single-pair input using signed route and namespace
		// facts; a caller cannot assign it to a different candidate or role.
		grant := l.maps[4]
		mask := l.tunnelCredentials[0].Scope().Role
		if mask != 5 && mask != 6 {
			return cryptov4.ErrConfiguration
		}
		id, _ := grant.Field("route_descriptor").Named("Route", "candidate_id").ByteString()
		index := -1
		candidates := l.maps[0].Field("candidates")
		for i := 0; i < candidates.Len(); i++ {
			candidateID, _ := candidates.Index(i).Named("Candidate", "candidate_id").ByteString()
			if bytes.Equal(id, candidateID) {
				index = i
			}
		}
		if index < 0 {
			return cryptov4.ErrConfiguration
		}
		l.tunnels[0] = leaseTunnelMaterial{index: uint64(index), role: protocolv4.Direction(mask - 5),
			maps: [2]*protocolv4.SignedMap{l.maps[4], l.maps[5]}, codecs: [2]*protocolv4.SignedMapCodec{l.codecs[4], l.codecs[5]},
			credentials: l.tunnelCredentials, validation: l.tunnelValidation}
		l.tunnelCount = 1
	}
	for i := 0; i < count; i++ {
		entry := &l.tunnels[i]
		l.tunnelCount = i + 1 // Include partial verification in failure cleanup.
		var originals [2]*protocolv4.SignedMap
		var wire [2][]byte
		var trust [2]*protocolv4.NamespaceTrustStore
		if trusted != nil {
			input := trusted.Tunnels[i]
			entry.index, entry.role = input.CandidateIndex, input.Role
			if input.LiveGrant != nil {
				entry.liveGrant, entry.pendingGrant = *input.LiveGrant, true
			}
			wire = [2][]byte{input.Grant, input.RelayCertificate}
			trust = [2]*protocolv4.NamespaceTrustStore{input.GrantTrust, input.RelayTrust}
		} else {
			input := c.Tunnels[i]
			entry.index, entry.role = input.CandidateIndex, input.Role
			if input.LiveGrant != nil {
				entry.liveGrant, entry.pendingGrant = *input.LiveGrant, true
			}
			originals = [2]*protocolv4.SignedMap{input.Grant, input.RelayCertificate}
			entry.validation = [2]protocolv4.CredentialValidation{input.GrantValidation, input.RelayValidation}
		}
		if entry.index >= 16 || entry.role > protocolv4.ServerToClient || i > 0 &&
			(entry.index < l.tunnels[i-1].index || entry.index == l.tunnels[i-1].index && entry.role <= l.tunnels[i-1].role) {
			return cryptov4.ErrConfiguration
		}
		if entry.pendingGrant {
			if l.source != "live_authority" || originals[0] != nil || len(wire[0]) != 0 {
				return cryptov4.ErrConfiguration
			}
			entry.validation[0] = entry.liveGrant.Validation
		}
		for part, schema := range []string{"Grant", "IdentityCertificate"} {
			var err error
			if i == 0 {
				entry.codecs[part] = l.codecs[4+part]
			} else {
				limit, e := protocolv4.SchemaByteLimit(schema)
				if e != nil {
					return e
				}
				entry.codecs[part], err = protocolv4.NewSignedMapCodec(schema, min(limit, c.MapBytes), c.MapNodes)
				if err != nil {
					return err
				}
			}
			if part == 0 && entry.pendingGrant {
				continue
			}
			if trusted != nil {
				if trust[part] == nil || len(wire[part]) == 0 {
					return cryptov4.ErrConfiguration
				}
				entry.maps[part], err = entry.codecs[part].VerifyCredential(wire[part], trust[part])
			} else {
				if originals[part] == nil {
					return cryptov4.ErrConfiguration
				}
				wire[part], err = originals[part].Bytes()
				if err == nil {
					entry.maps[part], err = entry.codecs[part].Verify(wire[part], originals[part].Key(), protocolv4.DecodeContext{})
				}
			}
			if i == 0 {
				l.maps[4+part] = entry.maps[part]
			}
			if err != nil {
				return err
			}
			entry.credentials[part], err = entry.maps[part].DetachCredential()
			if err != nil {
				return err
			}
			if trusted != nil {
				entry.validation[part], err = trust[part].ResolveCredential(entry.credentials[part])
				if err != nil {
					return err
				}
			}
		}
	}
	for i := 0; i < l.tunnelCount; i++ {
		entry := &l.tunnels[i]
		copy(entry.bindings[:3], l.validation[:])
		copy(entry.bindings[3:], entry.validation[:])
		copy(l.allBindings[3+2*i:], entry.validation[:])
		copy(l.allMaterialCredentials[3+2*i:], entry.credentials[:])
	}
	// Every candidate uses the same actual namespace owner for a given
	// tenant/authority. Separate snapshots across otherwise valid closures
	// would let candidate selection escape an already observed revocation.
	for i := range l.allCredentials() {
		if l.allBindings[i].Namespace == nil {
			return protocolv4.CBORFailure("credential_namespace_owner")
		}
		scope := l.credentialScopeAt(i)
		for j := 0; j < i; j++ {
			earlier := l.credentialScopeAt(j)
			if scope.Tenant == earlier.Tenant && scope.Authority == earlier.Authority &&
				l.allBindings[i].Namespace != l.allBindings[j].Namespace {
				return protocolv4.CBORFailure("credential_namespace_owner")
			}
		}
	}
	for i := 0; i < l.tunnelCount; i++ {
		entry := &l.tunnels[i]
		closure, err := l.endpointClosure(entry.index, entry.role)
		if err != nil {
			return err
		}
		if _, err = closure.CheckCurrent(entry.bindings[:], l.session.SessionNotAfterMS); err != nil {
			return err
		}
		if l.source == "preauthorized_pool" {
			_, authority, err := l.activation(entry.index)
			if err != nil {
				return err
			}
			if err = closure.MatchActivation(authority); err != nil {
				return err
			}
		}
		if other := l.tunnelMaterial(entry.index, 1-entry.role); other != nil && !other.pendingGrant && !entry.pendingGrant {
			for _, field := range []string{"pairing_id", "parent_ref", "route_descriptor", "attempt_id", "identity_digests", "service", "audience", "relay_identity_digest"} {
				if !bytes.Equal(entry.maps[0].Field(field).Encoded(), other.maps[0].Field(field).Encoded()) {
					return cryptov4.ErrConfiguration
				}
			}
		}
	}
	// Each represented endpoint role must have the entire signed pool set.
	// Incomplete material is refused before it enters a pool or starts racing.
	if l.source == "preauthorized_pool" {
		for role := protocolv4.ClientToServer; role <= protocolv4.ServerToClient; role++ {
			present := false
			for i := 0; i < l.tunnelCount; i++ {
				present = present || l.tunnels[i].role == role
			}
			if present || l.tunnelCount == 0 {
				if err := l.checkTunnelRole(role); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (l *ArtifactLease) checkTunnelRole(role protocolv4.Direction) error {
	if l.source != "preauthorized_pool" {
		return nil
	}
	indices := l.maps[1].Field("candidate_selection").Named("PoolSelectionRef", "candidate_indices")
	for i := 0; i < indices.Len(); i++ {
		index, ok := indices.Index(i).Uint()
		if !ok {
			return cryptov4.ErrConfiguration
		}
		if _, _, _, err := l.endpointCredentialMaps(index, role); err != nil {
			return err
		}
	}
	return nil
}

func (l *ArtifactLease) credentialScopeAt(index int) protocolv4.CredentialScope {
	if credential := l.allMaterialCredentials[index]; credential != nil {
		return credential.Scope()
	}
	if index >= 3 && (index-3)%2 == 0 {
		entry := &l.tunnels[(index-3)/2]
		if entry.pendingGrant {
			return entry.liveGrant.Scope
		}
	}
	return protocolv4.CredentialScope{}
}

func (l *ArtifactLease) endpointClosure(index uint64, role protocolv4.Direction) (*protocolv4.EndpointCredentials, error) {
	grant, relay, _, err := l.endpointCredentialMaps(index, role)
	if err != nil {
		return nil, err
	}
	if entry := l.tunnelMaterial(index, role); entry != nil && entry.pendingGrant {
		return protocolv4.BindLiveEndpointPreparation(role, l.maps[0], index, l.maps[2], l.maps[3], relay, entry.liveGrant)
	}
	return protocolv4.BindEndpointCredentials(role, l.maps[0], index, l.maps[2], l.maps[3], grant, relay)
}
