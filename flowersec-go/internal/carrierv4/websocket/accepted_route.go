package websocket

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ObserveAcceptedEndpoint reads only original HTTP/TLS and socket facts. Its
// caller must admit the finite string copies before calling it. It is not a
// certificate, trust or signed route authorization check.
func ObserveAcceptedEndpoint(r *http.Request, subprotocol string) (protocolv4.AcceptedWebSocketEndpoint, error) {
	var e protocolv4.AcceptedWebSocketEndpoint
	if r == nil || r.URL == nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.User != nil || r.URL.IsAbs() || len(r.Host) > 261 || len(r.URL.EscapedPath()) > 128 {
		return e, ErrEndpoint
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		} else if strings.Contains(host, ":") {
			return e, ErrEndpoint
		}
		port = "80"
		if r.TLS != nil {
			port = "443"
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || len(host) == 0 || len(host) > 253 {
		return e, ErrEndpoint
	}
	e.Host, e.Port, e.Path, e.Subprotocol = strings.Clone(host), uint16(n), strings.Clone(r.URL.EscapedPath()), subprotocol
	for key, values := range r.Header {
		if !strings.EqualFold(key, "Origin") {
			continue
		}
		if e.OriginPresent || len(values) != 1 || values[0] == "" || len(values[0]) > 512 {
			return e, ErrEndpoint
		}
		e.Origin, e.OriginPresent = strings.Clone(values[0]), true
	}
	if r.TLS != nil {
		e.TLS13 = r.TLS.HandshakeComplete && r.TLS.Version == tls.VersionTLS13
		if !e.TLS13 || r.TLS.NegotiatedProtocol != "" && r.TLS.NegotiatedProtocol != "http/1.1" {
			return e, ErrEndpoint
		}
	}
	if address, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		e.Local, _ = netip.ParseAddrPort(address.String())
	}
	e.Remote, _ = netip.ParseAddrPort(r.RemoteAddr)
	return e, nil
}

// CheckEnvironment binds the physical provider's original charge and shared
// owner before a prepared or accepted wrapper can take its lifecycle.
func (m *Messages) CheckEnvironment(environment resourcev4.Reference) error {
	if m == nil || m.owner == nil {
		return resourcev4.ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.preparing || m.conn == nil {
		return net.ErrClosed
	}
	if err := m.environment.Check(); err != nil {
		return err
	}
	return m.reservation.CheckSameEnvironment(environment)
}

// CheckAcceptedRoute is tied to the same canonical owner that performed the
// actual upgrade. Dialed connections and upgrades without original deployment
// policy cannot be promoted into a direct server Session. Close stays prompt;
// cleanup retains the policy call's actual tail and its original charge.
func (m *Messages) CheckAcceptedRoute(artifact *protocolv4.SignedMap, index uint64, policy protocolv4.HelloPolicy) (err error) {
	if m == nil || m.owner == nil {
		return resourcev4.ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.preparing || m.conn == nil {
		m.mu.Unlock()
		return net.ErrClosed
	}
	if m.checking || m.reading || m.writing {
		m.mu.Unlock()
		return ErrConcurrent
	}
	if m.checkAcceptedRoute == nil {
		m.mu.Unlock()
		return resourcev4.ErrConfiguration
	}
	if err = m.reservation.Check(); err == nil {
		err = m.environment.Check()
	}
	if err != nil {
		m.mu.Unlock()
		return err
	}
	check, endpoint := m.checkAcceptedRoute, m.acceptedEndpoint
	m.checking = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.checking = false
		if err == nil {
			if m.closed {
				err = net.ErrClosed
			} else if err = m.reservation.Check(); err == nil {
				err = m.environment.Check()
			}
		}
		m.cleanupLocked()
		m.signalLocked()
	}()
	if artifact == nil {
		return resourcev4.ErrConfiguration
	}
	session, err := artifact.SessionParameters()
	if err != nil {
		return err
	}
	if uint64(m.options.MaxMessageBytes) < uint64(session.Contract.Limits().MaxFrame)+protocolv4.EnvelopePrefixSize {
		return resourcev4.ErrCapacity
	}
	if err = artifact.CheckAcceptedWebSocket(index, endpoint, policy); err != nil {
		return err
	}
	return check(endpoint, artifact, index, policy)
}
