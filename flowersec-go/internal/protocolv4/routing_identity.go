package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
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
