package transportsecurity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
)

type tunnelIngress struct {
	carrier  artifactv3.Carrier
	endpoint string
	leaf     []byte
}

type tunnelIngressKey struct{}

// WithTunnelIngress records the listener's configured public URL and the actual
// leaf presented by its TLS stack, before inspecting the peer's admission.
func WithTunnelIngress(ctx context.Context, kind artifactv3.Carrier, endpoint string, state *tls.ConnectionState) context.Context {
	var leaf []byte
	if state != nil && state.Version == tls.VersionTLS13 && !state.DidResume && len(state.LocalCertificate) > 0 {
		leaf = state.LocalCertificate[0]
	}
	return context.WithValue(ctx, tunnelIngressKey{}, tunnelIngress{carrier: kind, endpoint: endpoint, leaf: leaf})
}

func MatchesTunnelIngress(ctx context.Context, decoded *artifactv3.DecodedRequest, now time.Time) bool {
	ingress, ok := ctx.Value(tunnelIngressKey{}).(tunnelIngress)
	if !ok || ingress.endpoint == "" || len(ingress.leaf) == 0 || decoded == nil || decoded.Request.PathKind != artifactv3.PathTunnel {
		return false
	}
	return matchesIngress(ingress, decoded, now)
}

func MatchesDirectIngress(decoded *artifactv3.DecodedRequest, kind artifactv3.Carrier, endpoint string, state *tls.ConnectionState, now time.Time) bool {
	if decoded == nil || decoded.Request.PathKind != artifactv3.PathDirect || state == nil || state.Version != tls.VersionTLS13 || state.DidResume || len(state.LocalCertificate) == 0 {
		return false
	}
	return matchesIngress(tunnelIngress{carrier: kind, endpoint: endpoint, leaf: state.LocalCertificate[0]}, decoded, now)
}

func matchesIngress(ingress tunnelIngress, decoded *artifactv3.DecodedRequest, now time.Time) bool {
	for _, candidate := range decoded.Request.Candidates {
		if candidate.ID != decoded.Request.ChosenCandidateID || candidate.Carrier != ingress.carrier || candidate.NormalizedURL != ingress.endpoint {
			continue
		}
		leaf, err := x509.ParseCertificate(ingress.leaf)
		if err != nil {
			return false
		}
		switch candidate.TLS.Mode {
		case artifactv3.TLSModeCA:
			u, err := url.Parse(ingress.endpoint)
			return err == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) && leaf.VerifyHostname(u.Hostname()) == nil
		case artifactv3.TLSModePin:
			policy, err := BuildClientTLS(&tls.Config{Time: func() time.Time { return now }}, ingress.endpoint, candidate.TLS, now)
			return err == nil && policy.VerifyConnection != nil && policy.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}) == nil
		}
	}
	return false
}
