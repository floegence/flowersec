package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// RoutingIdentity captures the authenticated logical endpoints, independently
// of certificate/key rotation and physical routes. It is only an equality
// fence; every new publication still requires current authorization. A peer
// with a different subject is not an implicitly authorized replacement.
func (a *EndpointAuthorization) RoutingIdentity() ([32]byte, error) {
	if a == nil {
		return [32]byte{}, CBORFailure("credential_authorization_owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.checkLocked(false); err != nil {
		return [32]byte{}, err
	}
	return a.closure.routingIdentity(), nil
}

func (e *EndpointCredentials) routingIdentity() [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("flowersec/v4/authenticated-routing-identity\x00"))
	_, _ = h.Write([]byte{byte(e.role)})
	var size [8]byte
	for _, credential := range e.credentials[:3] {
		s := credential.scope
		for _, value := range [...]string{s.Tenant, s.Authority, s.Audience, s.Subject, s.Profile} {
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = h.Write(size[:])
			_, _ = h.Write([]byte(value))
		}
	}
	var identity [32]byte
	h.Sum(identity[:0])
	return identity
}

// ErrUnapprovedRoutingPeer marks a currently authenticated peer outside the
// original binding's trusted finite replica mapping.
var ErrUnapprovedRoutingPeer = errors.New("protocolv4: authenticated peer is outside the trusted replica mapping")

// RoutingIdentityForPeers applies a trusted local replica allowlist to the
// authenticated peer subject only. All credential authority domains, tenant,
// audience, local caller and profile remain in the original equality fence.
// No peer-controlled field can grant membership in the allowlist.
func (a *EndpointAuthorization) RoutingIdentityForPeers(subjects [16][32]byte, count uint8) ([32]byte, error) {
	if a == nil || count == 0 || count > 16 {
		return [32]byte{}, CBORFailure("credential_authorization_owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.checkLocked(false); err != nil {
		return [32]byte{}, err
	}
	return a.closure.routingIdentityForPeers(subjects, count)
}

func (e *EndpointCredentials) routingIdentityForPeers(subjects [16][32]byte, count uint8) ([32]byte, error) {
	if e == nil || count == 0 || count > 16 || e.role != ClientToServer && e.role != ServerToClient {
		return [32]byte{}, CBORFailure("credential_role")
	}
	peer := 2
	if e.role == ServerToClient {
		peer = 1
	}
	if e.credentials[peer] == nil {
		return [32]byte{}, CBORFailure("credential_authorization_owner")
	}
	actual := sha256.Sum256([]byte(e.credentials[peer].scope.Subject))
	approved := false
	for j := uint8(0); j < count; j++ {
		approved = approved || subjects[j] == actual
	}
	if !approved {
		return [32]byte{}, ErrUnapprovedRoutingPeer
	}
	h := sha256.New()
	_, _ = h.Write([]byte("flowersec/v4/authenticated-replica-routing-identity\x00"))
	_, _ = h.Write([]byte{byte(e.role)})
	var size [8]byte
	for j, credential := range e.credentials[:3] {
		if credential == nil {
			return [32]byte{}, CBORFailure("credential_authorization_owner")
		}
		s := credential.scope
		values := [...]string{s.Tenant, s.Authority, s.Audience, s.Subject, s.Profile}
		if j == peer {
			values[3] = ""
		}
		for _, value := range values {
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = h.Write(size[:])
			_, _ = h.Write([]byte(value))
		}
	}
	var identity [32]byte
	h.Sum(identity[:0])
	return identity, nil
}
