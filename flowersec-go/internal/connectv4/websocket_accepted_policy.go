package connectv4

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// WebSocketAcceptedPolicy is the direct network policy for an original native
// TLS terminator. Tuple and Origin policy apply before upgrade, then the same
// actual connection and certificate are matched against the signed candidate.
// Roots/Clock are immutable admitted dependencies. CheckPolicy, when supplied,
// adds the host's request authorization after these structural/TLS checks.
// Private loopback and externally terminated TLS require their own explicit
// qualified deployment adapters; they cannot use this local TLS capability.
type WebSocketAcceptedPolicy struct {
	TLS               *WebSocketTLSListener
	Clock             *timev4.Clock
	Roots             *x509.CertPool
	Host, Path        string
	Port              uint16
	Origins           []string
	AllowAbsentOrigin bool
}

func (p WebSocketAcceptedPolicy) validate() error {
	if p.TLS == nil || p.Clock == nil || p.Host == "" || len(p.Host) > 253 || p.Port == 0 ||
		p.Path != "/flowersec/v4/direct" || len(p.Origins) > 16 || !p.AllowAbsentOrigin && len(p.Origins) == 0 {
		return resourcev4.ErrConfiguration
	}
	for i, origin := range p.Origins {
		if origin == "" || len(origin) > 512 {
			return resourcev4.ErrConfiguration
		}
		for _, prior := range p.Origins[:i] {
			if prior == origin {
				return resourcev4.ErrConfiguration
			}
		}
	}
	return nil
}

func acceptedWebSocketPolicyCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(acceptedPolicyMessages{})) + tlspolicy.BackingBytes() + 32768,
		resourcev4.Items: 1}
}

type acceptedPolicyMessages struct {
	*websocket.Messages
	mu           sync.Mutex
	backing      resourcev4.Reference
	clock        *timev4.Clock
	roots        *x509.CertPool
	tls          websocketTLSBinding
	verification tlspolicy.Verification
	bound        bool
	artifact     [32]byte
	index        uint64
}

func (p WebSocketAcceptedPolicy) upgrade(r *http.Request, cfg websocket.UpgradeConfig, backing resourcev4.Reference) (websocket.UpgradeConfig, *acceptedPolicyMessages, error) {
	if err := p.validate(); err != nil {
		return cfg, nil, err
	}
	if cfg.Subprotocol != websocket.SubprotocolDirect || cfg.CheckAcceptedRoute != nil {
		return cfg, nil, resourcev4.ErrConfiguration
	}
	if err := backing.CheckSameEnvironment(p.TLS.reservation); err != nil {
		return cfg, nil, err
	}
	binding, err := p.TLS.accepted(r)
	if err != nil {
		return cfg, nil, err
	}
	if err = binding.socket.begin(); err != nil {
		return cfg, nil, err
	}
	clockMatches := p.Clock == p.TLS.config.Clock
	binding.socket.end()
	if !clockMatches {
		return cfg, nil, resourcev4.ErrConfiguration
	}
	m := &acceptedPolicyMessages{backing: backing, clock: p.Clock, roots: p.Roots, tls: binding}
	check := cfg.CheckPolicy
	cfg.CheckPolicy = func(request *http.Request) error {
		if err := backing.Check(); err != nil {
			return err
		}
		actual, err := p.TLS.accepted(request)
		if err != nil {
			return err
		}
		if actual != binding {
			return websocket.ErrEndpoint
		}
		e, err := websocket.ObserveAcceptedEndpoint(request, cfg.Subprotocol)
		if err != nil {
			return err
		}
		if e.Host != p.Host || e.Port != p.Port || e.Path != p.Path || !e.TLS13 {
			return websocket.ErrEndpoint
		}
		allowed := !e.OriginPresent && p.AllowAbsentOrigin
		for _, origin := range p.Origins {
			allowed = allowed || e.OriginPresent && e.Origin == origin
		}
		if !allowed {
			return websocket.ErrEndpoint
		}
		if check != nil {
			return check(request)
		}
		return nil
	}
	cfg.CheckAcceptedRoute = m.verifyRoute
	return cfg, m, nil
}

// The Messages owner serializes these finite checks and retains their actual
// tails. The first successful check freezes the original active pin set and
// matched window; repeats never select a newer pin or a different Artifact.
func (m *acceptedPolicyMessages) verifyRoute(_ protocolv4.AcceptedWebSocketEndpoint, artifact *protocolv4.SignedMap, index uint64, _ protocolv4.HelloPolicy) error {
	if err := m.backing.Check(); err != nil {
		return err
	}
	digest, err := artifact.Digest("artifact_digest")
	if err != nil {
		return err
	}
	m.mu.Lock()
	bound, original, originalIndex, verification := m.bound, m.artifact, m.index, m.verification
	m.mu.Unlock()
	now, err := m.clock.Sample()
	if err != nil {
		return err
	}
	if bound {
		if digest != original || index != originalIndex {
			return websocket.ErrEndpoint
		}
		return verification.Check(now.Interval)
	}
	if err = m.tls.socket.begin(); err != nil {
		return err
	}
	defer m.tls.socket.end()
	leg := artifact.Field("candidates").Index(int(index)).Named("Candidate", "direct_leg")
	policy, err := tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
	if err != nil {
		return err
	}
	prepared, err := policy.Prepare(now.Interval)
	if err != nil {
		return err
	}
	host, ok := leg.Named("Leg", "host").Text()
	if !ok {
		return websocket.ErrEndpoint
	}
	state := m.tls.connection.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume {
		return tlspolicy.ErrCertificate
	}
	// The immutable TLS config has exactly this certificate and no alternate
	// GetCertificate/GetConfigForClient, client-auth or resumption path. This
	// is its local leaf, never the unrelated PeerCertificates client chain.
	state.PeerCertificates = m.tls.socket.listener.chain
	verification, err = prepared.Verify(state, host, m.roots, now.Interval)
	if err != nil {
		return err
	}
	if err = m.backing.Check(); err != nil {
		return err
	}
	m.mu.Lock()
	m.bound, m.artifact, m.index, m.verification = true, digest, index, verification
	m.mu.Unlock()
	return nil
}

func (m *acceptedPolicyMessages) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	g, err := m.Messages.ConnectionGuarantees()
	if err != nil {
		return g, err
	}
	if err = m.backing.Check(); err != nil {
		return g, err
	}
	m.mu.Lock()
	bound, verification := m.bound, m.verification
	m.mu.Unlock()
	// Before the original Hello resolves its signed route, this exposes only
	// the actual carrier's accepted-side observations. Admission still requires
	// verifyRoute, and accepted TLS never attests remote consumer controls.
	if bound {
		now, err := m.clock.Sample()
		if err != nil {
			return g, err
		}
		if err = verification.Check(now.Interval); err != nil {
			return g, err
		}
	}
	return g, nil
}

func (m *acceptedPolicyMessages) Retire() error {
	if err := m.Messages.Retire(); err != nil {
		return err
	}
	m.backing.Release()
	return nil
}

func captureAcceptedPolicy(p WebSocketAcceptedPolicy) *WebSocketAcceptedPolicy {
	p.Host, p.Path = strings.Clone(p.Host), strings.Clone(p.Path)
	p.Origins = append([]string(nil), p.Origins...)
	for i, origin := range p.Origins {
		p.Origins[i] = strings.Clone(origin)
	}
	return &p
}
