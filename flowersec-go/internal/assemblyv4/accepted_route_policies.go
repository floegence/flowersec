package assemblyv4

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// These entries belong to their original listener reservation. The peer can
// select only a complete route independently installed by the listener owner.
// Every use verifies the actual certificate against that exact signed policy.
type acceptedRoutePolicy struct {
	wire   []byte
	policy tlspolicy.Policy
}
type acceptedRoutePolicies struct {
	decoder *protocolv4.Decoder
	entries []acceptedRoutePolicy
	used    uint16
}

func acceptedRoutePoliciesBacking(capacity uint16, routeBytes, routeNodes int) (uint64, error) {
	if capacity > 64 {
		return 0, resourcev4.ErrConfiguration
	}
	if capacity == 0 {
		return 0, nil
	}
	decoder, err := protocolv4.DecoderBackingBytes(routeBytes, routeNodes)
	if err != nil {
		return 0, err
	}
	return decoder + uint64(capacity)*(uint64(routeBytes)+uint64(unsafe.Sizeof(acceptedRoutePolicy{}))), nil
}
func newAcceptedRoutePolicies(capacity uint16, routeBytes, routeNodes int) (acceptedRoutePolicies, error) {
	if capacity == 0 {
		return acceptedRoutePolicies{}, nil
	}
	decoder, err := protocolv4.NewDecoder(routeBytes, routeNodes)
	if err != nil {
		return acceptedRoutePolicies{}, err
	}
	return acceptedRoutePolicies{decoder: decoder, entries: make([]acceptedRoutePolicy, capacity)}, nil
}
func (p *acceptedRoutePolicies) install(original *protocolv4.Document, wire []byte, certificates []*x509.Certificate, host string, roots *x509.CertPool, now timev4.Interval) error {
	if p.decoder == nil {
		return resourcev4.ErrCapacity
	}
	for i := uint16(0); i < p.used; i++ {
		if bytes.Equal(p.entries[i].wire, wire) {
			return nil
		}
	}
	if int(p.used) == len(p.entries) {
		return resourcev4.ErrCapacity
	}
	document, err := p.decoder.DecodeMap(wire, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	defer document.Release()
	if !original.SameDirectRouteEndpoint(document) {
		return protocolv4.CBORFailure("accepted_listener_binding")
	}
	policy, err := tlspolicy.Capture(document.Root().Named("Route", "direct_leg").Named("Leg", "tls_policy"))
	if err != nil {
		return err
	}
	if err = verifyAcceptedRoutePolicy(policy, certificates, host, roots, now); err != nil {
		return err
	}
	p.entries[p.used] = acceptedRoutePolicy{wire: bytes.Clone(wire), policy: policy}
	p.used++
	return nil
}
func verifyAcceptedRoutePolicy(policy tlspolicy.Policy, certificates []*x509.Certificate, host string, roots *x509.CertPool, now timev4.Interval) error {
	prepared, err := policy.Prepare(now)
	if err != nil {
		return err
	}
	if !policy.RequiresRoots() {
		roots = nil
	}
	_, err = prepared.Verify(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: certificates}, host, roots, now)
	return err
}
func (p *acceptedRoutePolicies) check(wire []byte, certificates []*x509.Certificate, host string, roots *x509.CertPool, now timev4.Interval) error {
	for i := uint16(0); i < p.used; i++ {
		entry := &p.entries[i]
		if bytes.Equal(entry.wire, wire) {
			return verifyAcceptedRoutePolicy(entry.policy, certificates, host, roots, now)
		}
	}
	return protocolv4.CBORFailure("accepted_listener_binding")
}
func (p *acceptedRoutePolicies) release() {
	for i := range p.entries {
		clear(p.entries[i].wire)
		p.entries[i] = acceptedRoutePolicy{}
	}
	p.entries = nil
	p.decoder = nil
	p.used = 0
}

// InstallAcceptedRoute installs an independently trusted complete direct route
// for this original endpoint. A peer cannot call it through wire input. The
// original listener envelope reserves every entry before opening the socket.
func (s *QUICServer) InstallAcceptedRoute(route []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkCertificateLocked(); err != nil {
		return err
	}
	now, err := s.sampleLocked()
	if err != nil {
		return err
	}
	return s.acceptedRoutes.install(s.document, route, s.certificates, s.host, s.c.Roots, now.Interval)
}
func (s *WebTransportServer) InstallAcceptedRoute(route []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkCertificateLocked(); err != nil {
		return err
	}
	now, err := s.sampleLocked()
	if err != nil {
		return err
	}
	return s.acceptedRoutes.install(s.document, route, s.certificates, s.host, s.c.Roots, now.Interval)
}
func (s *WebSocketServer) InstallAcceptedRoute(route []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkCertificateLocked(); err != nil {
		return err
	}
	now, err := s.sampleLocked()
	if err != nil {
		return err
	}
	return s.acceptedRoutes.install(s.document, route, s.certificates, s.host, s.c.Roots, now.Interval)
}
