package interopharness

import (
	"crypto/tls"
	"crypto/x509"
	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"net/netip"
	"time"
)

// OperationDeadlineMS is configured locally before original authority creation.
// Every setup phase uses this ceiling; the caller context retains the single
// overall operation deadline and cannot be extended by a phase or provider.
func (r *Reporter) AuthorityOperationMS() uint64 { return r.operationMS(10000) }
func (r *Reporter) operationMS(fallback uint64) uint64 {
	if r.OperationDeadlineMS == 0 {
		return fallback
	}
	if r.OperationDeadlineMS > 90000 {
		r.Fatal("engineering operation exceeds the original supported preparation window")
	}
	return r.OperationDeadlineMS
}
func (r *Reporter) operationDuration(fallback time.Duration) time.Duration {
	return time.Duration(r.operationMS(uint64(fallback/time.Millisecond))) * time.Millisecond
}
func (r *Reporter) webSocketProvider() fs.WebSocketProviderOptions {
	options := WebSocketProvider()
	options.HandshakeTimeout = r.operationDuration(options.HandshakeTimeout)
	options.MessageTimeout = r.operationDuration(options.MessageTimeout)
	return options
}
func (r *Reporter) quicProviderFor(streams uint32) fs.QUICProviderOptions {
	options := QUICProviderFor(streams)
	options.Limits.HandshakeIdleTimeout = r.operationDuration(options.Limits.HandshakeIdleTimeout)
	options.Limits.MaxIdleTimeout = max(options.Limits.MaxIdleTimeout, options.Limits.HandshakeIdleTimeout)
	return options
}
func (r *Reporter) webTransportProviderFor(streams uint32) fs.WebTransportProviderOptions {
	options := WebTransportProviderFor(streams)
	options.Limits.HandshakeIdleTimeout = r.operationDuration(options.Limits.HandshakeIdleTimeout)
	options.Limits.MaxIdleTimeout = max(options.Limits.MaxIdleTimeout, options.Limits.HandshakeIdleTimeout)
	return options
}

func (r *Reporter) nativeScopedLeg(carrier string, address netip.AddrPort, certificate tls.Certificate, roots *x509.CertPool, scope assemblyv4.NativeDialScope) runtimehost.NativeRelayLeg {
	leg := engineeringRelayNativeScopedLeg(carrier, address, certificate, roots, scope)
	leg.WebSocket = r.webSocketProvider()
	leg.QUIC = r.quicProviderFor(142)
	leg.WebTransport = r.webTransportProviderFor(142)
	return leg
}
