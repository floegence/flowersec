package connectv4

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// WebSocketPolicy is the native direct default. Clock and CA roots are fixed
// immutable, preadmitted dependencies of the source snapshot. Numeric endpoint
// preparation remains outside this policy; each request chooses one address.
// It never imports caller TLS callbacks, client certificates or session caches.
type WebSocketPolicy struct {
	Clock *timev4.Clock
	Roots *x509.CertPool
}

type policyMessages struct {
	*websocket.Messages
	policy       tlspolicy.Prepared
	verification tlspolicy.Verification
	clock        *timev4.Clock
	backing      resourcev4.Reference
	network      bool
}

func websocketPolicyCharge() (resourcev4.Vector, error) {
	decoder, err := protocolv4.DecoderBackingBytes(16384, 4096)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: decoder + uint64(unsafe.Sizeof(policyMessages{})) + tlspolicy.BackingBytes() + 32768, resourcev4.Items: 1}, nil
}

// The caller owns backing before this parser, certificate policy or TLS
// callback can allocate or execute. Error returns preserve that ownership.
func (c WebSocketPolicy) prepare(request sessionv4.CarrierPreparationRequest, dial websocket.DialConfig, backing resourcev4.Reference) (websocket.DialConfig, *policyMessages, error) {
	if c.Clock == nil || !request.Config.Deadline.BelongsTo(c.Clock) || dial.TLSConfig != nil || dial.CheckPolicy != nil {
		return dial, nil, resourcev4.ErrConfiguration
	}
	decoder, err := protocolv4.NewDecoder(16384, 4096)
	if err != nil {
		return dial, nil, err
	}
	doc, err := decoder.DecodeMap(request.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return dial, nil, err
	}
	defer doc.Release()
	if err = doc.MatchCandidateRoute(request.Config.Candidate); err != nil {
		return dial, nil, err
	}
	path, _ := doc.Root().Named("Route", "path_kind").Uint()
	if path != 0 {
		return dial, nil, resourcev4.ErrConfiguration
	}
	leg := doc.Root().Named("Route", "direct_leg")
	carrier, _ := leg.Named("Leg", "carrier").Uint()
	if carrier != 1 {
		return dial, nil, resourcev4.ErrConfiguration
	}
	u, err := url.Parse(dial.URL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
		return dial, nil, resourcev4.ErrConfiguration
	}
	host, hostOK := leg.Named("Leg", "host").Text()
	port, portOK := leg.Named("Leg", "port").Uint()
	pathText, pathOK := leg.Named("Leg", "path").Text()
	subprotocol, subOK := leg.Named("Leg", "subprotocol").Text()
	actualPort := uint64(443)
	if u.Scheme == "ws" {
		actualPort = 80
	}
	if u.Port() != "" {
		actualPort, err = strconv.ParseUint(u.Port(), 10, 16)
	}
	if err != nil || !hostOK || !portOK || !pathOK || !subOK || u.Hostname() != host || u.Path != pathText || actualPort != port || dial.Subprotocol != subprotocol || !dial.RemoteAddress.IsValid() || uint64(dial.RemoteAddress.Port()) != port {
		return dial, nil, websocket.ErrEndpoint
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil && ip.Unmap() != dial.RemoteAddress.Addr().Unmap() {
		return dial, nil, websocket.ErrEndpoint
	}
	origin := ""
	for name, values := range dial.Header {
		if !strings.EqualFold(name, "Origin") || len(values) != 1 || origin != "" || values[0] == "" {
			return dial, nil, resourcev4.ErrConfiguration
		}
		origin = values[0]
	}
	access, _ := leg.Named("Leg", "access_class").Uint()
	m := &policyMessages{clock: c.Clock, backing: backing, network: access == 0}
	if access == 1 {
		want, _ := leg.Named("Leg", "origin").Text()
		ip, err := netip.ParseAddr(host)
		if err != nil || u.Scheme != "ws" || !ip.IsLoopback() || !dial.RemoteAddress.Addr().IsLoopback() || origin != want {
			return dial, nil, websocket.ErrEndpoint
		}
	} else if access == 0 {
		if u.Scheme != "wss" {
			return dial, nil, websocket.ErrEndpoint
		}
		originPolicy := leg.Named("Leg", "origin_policy")
		if origin == "" {
			if originPolicy.Encoded() != nil {
				absent, _ := originPolicy.Named("OriginPolicy", "allow_absent").Bool()
				if !absent {
					return dial, nil, resourcev4.ErrConfiguration
				}
			}
		} else {
			origins := originPolicy.Named("OriginPolicy", "origins")
			allowed := false
			for i := range origins.Len() {
				value, _ := origins.Index(i).Text()
				allowed = allowed || value == origin
			}
			if !allowed {
				return dial, nil, resourcev4.ErrConfiguration
			}
		}
		policy, err := tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
		if err != nil {
			return dial, nil, err
		}
		if policy.RequiresRoots() && c.Roots == nil {
			return dial, nil, resourcev4.ErrConfiguration
		}
		now, err := c.Clock.Sample()
		if err != nil {
			return dial, nil, err
		}
		m.policy, err = policy.Prepare(now.Interval)
		if err != nil {
			return dial, nil, err
		}
		// The original callback performs both CA/SAN or exact DER policy and
		// trusted-time validation. Go TLS still verifies CertificateVerify and
		// Finished. No insecure result can escape a failed callback.
		dial.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
			VerifyConnection: func(state tls.ConnectionState) error {
				if err := backing.Check(); err != nil {
					return err
				}
				now, err := c.Clock.Sample()
				if err != nil {
					return err
				}
				m.verification, err = m.policy.Verify(state, host, c.Roots, now.Interval)
				return err
			}}
	} else {
		return dial, nil, resourcev4.ErrConfiguration
	}
	// These detached values are captured once; the borrowed Route decoder is
	// released before dialing and cannot be retained by a provider callback.
	expectedURL, address := dial.URL, dial.RemoteAddress
	dial.CheckPolicy = func(actual *url.URL, actualAddress netip.AddrPort, headers http.Header) error {
		if actual.String() != expectedURL || actualAddress != address || headers.Get("Origin") != origin {
			return websocket.ErrEndpoint
		}
		return backing.Check()
	}
	return dial, m, nil
}

func (m *policyMessages) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	g, err := m.Messages.ConnectionGuarantees()
	if err != nil {
		return g, err
	}
	if err = m.backing.Check(); err != nil {
		return g, err
	}
	if m.network {
		now, err := m.clock.Sample()
		if err != nil {
			return g, err
		}
		if err = m.verification.Check(now.Interval); err != nil {
			return g, err
		}
	}
	return g, nil
}

func (m *policyMessages) Retire() error {
	if err := m.Messages.Retire(); err != nil {
		return err
	}
	m.backing.Release()
	return nil
}

// These explicit methods document that the original WebSocket owner remains
// responsible for real physical/callback cleanup; the policy adds no waiter.
func (m *policyMessages) Close() error                          { return m.Messages.Close() }
func (m *policyMessages) WaitCleanup(ctx context.Context) error { return m.Messages.WaitCleanup(ctx) }
