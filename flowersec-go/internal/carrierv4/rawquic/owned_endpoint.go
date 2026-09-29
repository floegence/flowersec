package rawquic

import (
	"crypto/tls"
	"net"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// AcceptedEndpoint is a detached observation of the original accepted native
// connection. It contains neither peer authorization nor a Session capability.
type AcceptedEndpoint struct {
	Local, Remote    netip.AddrPort
	ServerName, ALPN string
	TLS13            bool
}

func (p *OwnedConnection) AcceptedEndpoint() (AcceptedEndpoint, error) {
	if p == nil || p.ownedConnection == nil {
		return AcceptedEndpoint{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return AcceptedEndpoint{}, err
	}
	if p.client {
		return AcceptedEndpoint{}, resourcev4.ErrOwner
	}
	state := p.session.conn.ConnectionState()
	if !state.TLS.HandshakeComplete || state.TLS.Version != tls.VersionTLS13 || state.Used0RTT || state.TLS.DidResume || !validALPN(state.TLS.NegotiatedProtocol) {
		return AcceptedEndpoint{}, ErrInvalidTLS
	}
	local, localOK := p.session.conn.LocalAddr().(*net.UDPAddr)
	remote, remoteOK := p.session.conn.RemoteAddr().(*net.UDPAddr)
	if !localOK || !remoteOK {
		return AcceptedEndpoint{}, resourcev4.ErrOwner
	}
	endpoint := AcceptedEndpoint{Local: local.AddrPort(), Remote: remote.AddrPort(), ServerName: state.TLS.ServerName,
		ALPN: state.TLS.NegotiatedProtocol, TLS13: true}
	if !endpoint.Local.IsValid() || !endpoint.Remote.IsValid() || endpoint.Local.Port() == 0 || endpoint.Remote.Port() == 0 ||
		endpoint.Local.Addr().Zone() != "" || endpoint.Remote.Addr().Zone() != "" {
		return AcceptedEndpoint{}, resourcev4.ErrOwner
	}
	return endpoint, nil
}
