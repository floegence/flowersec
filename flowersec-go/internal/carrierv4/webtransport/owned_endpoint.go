package webtransport

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
)

// AcceptedEndpoint is detached evidence from the original CONNECT and socket.
// It is not a credential, application identity, or provider qualification.
type AcceptedEndpoint struct {
	Local, Remote                        netip.AddrPort
	ServerName, ALPN, Host, Path, Origin string
	OriginPresent, TLS13                 bool
}

func acceptedEndpoint(conn *quic.Conn, r *http.Request) (AcceptedEndpoint, error) {
	state := conn.ConnectionState()
	if !state.TLS.HandshakeComplete || state.TLS.Version != tls.VersionTLS13 || state.Used0RTT || state.TLS.DidResume || state.TLS.NegotiatedProtocol != "h3" {
		return AcceptedEndpoint{}, ErrInvalidTLS
	}
	local, localOK := conn.LocalAddr().(*net.UDPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.UDPAddr)
	if !localOK || !remoteOK {
		return AcceptedEndpoint{}, ErrInvalidSession
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != strconv.Itoa(local.Port) {
		return AcceptedEndpoint{}, ErrInvalidURL
	}
	count, origin := headerValue(r.Header, "Origin")
	if count > 1 || count == 1 && validateOrigin(origin) != nil {
		return AcceptedEndpoint{}, ErrInvalidURL
	}
	return AcceptedEndpoint{Local: local.AddrPort(), Remote: remote.AddrPort(), Host: host, Path: r.URL.Path,
		ServerName: state.TLS.ServerName, ALPN: state.TLS.NegotiatedProtocol, TLS13: true,
		Origin: origin, OriginPresent: count == 1}, nil
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
	return p.endpoint, nil
}
