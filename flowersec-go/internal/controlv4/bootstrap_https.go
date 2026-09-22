// Package controlv4 supplies bounded control transports for original v4 owners.
package controlv4

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/numeric"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrResponse = errors.New("controlv4: invalid bounded control response")
	ErrBusy     = errors.New("controlv4: original control read is still running")
)

// HTTPSBootstrapConfig is an independently installed control endpoint. The
// selected numeric address is bound to the HTTPS origin by the trusted host;
// DNS preparation is outside this adapter. The service must expose current
// linearizable trust/authority state independently of the consumer's storage.
//
// Requests use GET <BaseURL>/bootstrap?tenant_id=...&revocation_authority_id=...
// &nonce=<hex> and GET <BaseURL>/state?digest=<hex>&encoded_bytes=<decimal>.
// Both return HTTP/1.1 200, application/cbor and an explicit Content-Length.
// Responses do not authenticate themselves: NamespaceOnlineBootstrap verifies
// the exact nonce/config/Head signatures and complete State digest separately.
type HTTPSBootstrapConfig struct {
	BaseURL                            string
	RemoteAddress                      netip.AddrPort
	TLS                                *tls.Config
	HeaderBytes                        uint32
	Timeout                            time.Duration
	RuntimeBytes, ProviderRuntimeBytes uint64
}

type HTTPSBootstrapProvider struct {
	mu                        sync.Mutex
	config                    HTTPSBootstrapConfig
	base                      url.URL
	tls                       *tls.Config
	reservation, dependencies resourcev4.Reference
	active                    net.Conn
	stop, done                chan struct{}
	busy, closed, retired     bool
	complete                  bool
}

func HTTPSBootstrapCharge(c HTTPSBootstrapConfig) (resourcev4.Vector, error) {
	if len(c.BaseURL) == 0 || len(c.BaseURL) > 2048 || c.HeaderBytes < 1024 || c.HeaderBytes > 65536 || c.Timeout <= 0 || c.Timeout > 90*time.Second || c.RuntimeBytes == 0 || c.ProviderRuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(HTTPSBootstrapProvider{})) + 8*uint64(len(c.BaseURL)) + 8192,
		resourcev4.ProviderBytes: 64*uint64(c.HeaderBytes) + uint64(unsafe.Sizeof(tls.Config{})) + uint64(unsafe.Sizeof(tls.Conn{})) + uint64(unsafe.Sizeof(bufio.Reader{})) + 4096,
		resourcev4.Items:         1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 2, resourcev4.Connections: 1, resourcev4.NativeHandles: 2, resourcev4.TLSHandshakes: 1}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes, resourcev4.ProviderBytes: c.ProviderRuntimeBytes})
}

// NewHTTPSBootstrapProvider admits one serial physical read position. TLS trust
// stores, client certificates and policy callbacks are immutable dependencies
// admitted by the caller; their actual callback tails remain part of each call.
// It has no pool, resolver, redirect, retry, proxy, cookie jar or decompressor.
func NewHTTPSBootstrapProvider(c HTTPSBootstrapConfig, reservation, dependenciesBorrow resourcev4.Reference) (_ *HTTPSBootstrapProvider, err error) {
	charge, err := HTTPSBootstrapCharge(c)
	if err != nil {
		return nil, err
	}
	if err = numeric.CheckPlatform(c.RemoteAddress); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || strings.ContainsAny(c.BaseURL, "\r\n") {
		return nil, resourcev4.ErrConfiguration
	}
	port := uint64(443)
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
	}
	if err != nil || port != uint64(c.RemoteAddress.Port()) {
		return nil, numeric.ErrEndpoint
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && ip.Unmap() != c.RemoteAddress.Addr().Unmap() {
		return nil, numeric.ErrEndpoint
	}
	if c.TLS != nil && (c.TLS.InsecureSkipVerify || c.TLS.ServerName != "" && c.TLS.ServerName != u.Hostname() || c.TLS.MaxVersion != 0 && c.TLS.MaxVersion < tls.VersionTLS13 || c.TLS.KeyLogWriter != nil) {
		return nil, resourcev4.ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(dependenciesBorrow); err != nil {
		return nil, err
	}
	dependency, err := dependenciesBorrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		dependency.Release()
		return nil, err
	}
	config := &tls.Config{}
	if c.TLS != nil {
		config = c.TLS.Clone()
	}
	config.MinVersion, config.ServerName, config.NextProtos = tls.VersionTLS13, u.Hostname(), []string{"http/1.1"}
	config.ClientSessionCache = nil
	c.TLS = nil
	c.BaseURL = strings.Clone(c.BaseURL)
	u.Path = strings.TrimSuffix(u.Path, "/")
	return &HTTPSBootstrapProvider{config: c, base: *u, tls: config, reservation: owned, dependencies: dependency, stop: make(chan struct{}), done: make(chan struct{})}, nil
}

func (p *HTTPSBootstrapProvider) Query(ctx context.Context, r protocolv4.NamespaceBootstrapRequest, out []byte) (int, error) {
	if len(r.Tenant) == 0 || len(r.Tenant) > 128 || len(r.Authority) == 0 || len(r.Authority) > 128 || r.Nonce == ([32]byte{}) || len(out) < 1 || len(out) > 270336 {
		return 0, resourcev4.ErrConfiguration
	}
	return p.read(ctx, "/bootstrap", r, protocolv4.NamespaceContent{}, out, false)
}

func (p *HTTPSBootstrapProvider) Fetch(ctx context.Context, k protocolv4.NamespaceContent, out []byte) (int, error) {
	if k.EncodedBytes == 0 || k.EncodedBytes != uint64(len(out)) {
		return 0, resourcev4.ErrConfiguration
	}
	return p.read(ctx, "/state", protocolv4.NamespaceBootstrapRequest{}, k, out, true)
}

// Trust and Head are ordinary signed refresh reads. They never use the
// nonce-bound cold-start response as recovery evidence for a live namespace.
func (p *HTTPSBootstrapProvider) Trust(ctx context.Context, r protocolv4.NamespaceRefreshRequest, out []byte) (int, error) {
	return p.refresh(ctx, "/trust", "TrustConfig", r, out)
}

func (p *HTTPSBootstrapProvider) Head(ctx context.Context, r protocolv4.NamespaceRefreshRequest, out []byte) (int, error) {
	return p.refresh(ctx, "/head", "FreshnessHead", r, out)
}

func (p *HTTPSBootstrapProvider) refresh(ctx context.Context, path, schema string, r protocolv4.NamespaceRefreshRequest, out []byte) (int, error) {
	limit, err := protocolv4.SchemaByteLimit(schema)
	if err != nil || len(r.Tenant) == 0 || len(r.Tenant) > 128 || len(r.Authority) == 0 || len(r.Authority) > 128 || len(out) < 1 || len(out) > limit {
		return 0, resourcev4.ErrConfiguration
	}
	return p.read(ctx, path, protocolv4.NamespaceBootstrapRequest{Tenant: r.Tenant, Authority: r.Authority}, protocolv4.NamespaceContent{}, out, false)
}

func (p *HTTPSBootstrapProvider) read(ctx context.Context, path string, bootstrap protocolv4.NamespaceBootstrapRequest, content protocolv4.NamespaceContent, out []byte, exact bool) (n int, err error) {
	if ctx == nil {
		return 0, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.retired {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	if p.busy {
		p.mu.Unlock()
		return 0, ErrBusy
	}
	if err = p.reservation.Check(); err == nil {
		err = p.dependencies.Check()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		p.mu.Unlock()
		return 0, err
	}
	p.busy = true
	cfg, endpoint, tlsConfig := p.config, p.base, p.tls
	p.mu.Unlock()
	call, cancel := context.WithCancelCause(ctx)
	stop, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-stop:
			return
		case <-call.Done():
		case <-p.stop:
			cancel(net.ErrClosed)
		}
		p.mu.Lock()
		conn := p.active
		p.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	}()
	var conn net.Conn
	var response *http.Response
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		close(stop)
		<-exited
		cancel(nil)
		p.mu.Lock()
		if cause := context.Cause(call); cause != nil && cause != context.Canceled {
			err = cause
		}
		if cause := ctx.Err(); cause != nil {
			err = cause
		}
		if p.closed {
			err = net.ErrClosed
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.dependencies.Check()
		}
		if err != nil {
			clear(out)
			n = 0
		}
		p.active, p.busy = nil, false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	deadline := time.Now().Add(cfg.Timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	conn, err = numeric.Connect(call, cfg.RemoteAddress, deadline)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	if p.closed {
		err = net.ErrClosed
	} else {
		err = call.Err()
	}
	if err == nil {
		p.active = conn
	}
	p.mu.Unlock()
	if err != nil {
		return 0, err
	}
	secured := tls.Client(conn, tlsConfig)
	if err = secured.Handshake(); err != nil {
		return 0, err
	}
	if proto := secured.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
		return 0, ErrResponse
	}
	var query url.Values
	endpoint.Path += path
	if exact {
		query = url.Values{"digest": {hex.EncodeToString(content.Digest[:])}, "encoded_bytes": {strconv.FormatUint(content.EncodedBytes, 10)}}
	} else {
		query = url.Values{"tenant_id": {bootstrap.Tenant}, "revocation_authority_id": {bootstrap.Authority}}
		if path == "/bootstrap" {
			query.Set("nonce", hex.EncodeToString(bootstrap.Nonce[:]))
		}
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(call, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Close = true
	request.Header.Set("Accept", "application/cbor")
	request.Header.Set("Cache-Control", "no-store")
	// A TLS policy callback can outlive Close or caller cancellation. Observe
	// the original gate before starting HTTP publication; the cancellation
	// observer need not have been scheduled when that callback returns.
	p.mu.Lock()
	if p.closed {
		err = net.ErrClosed
	} else {
		err = call.Err()
	}
	if err == nil {
		err = p.reservation.Check()
	}
	if err == nil {
		err = p.dependencies.Check()
	}
	p.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if err = request.Write(secured); err != nil {
		return 0, err
	}
	header := &headerReader{reader: secured, remaining: int64(cfg.HeaderBytes), active: true}
	reader := bufio.NewReaderSize(header, 4096)
	response, err = http.ReadResponse(reader, request)
	if err != nil {
		return 0, err
	}
	header.active = false
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.StatusCode != http.StatusOK || len(response.TransferEncoding) != 0 || response.ContentLength <= 0 || response.ContentLength > int64(len(out)) || exact && response.ContentLength != int64(len(out)) || response.Header.Get("Content-Encoding") != "" || response.Header.Get("Content-Type") != "application/cbor" {
		return 0, ErrResponse
	}
	n, err = io.ReadFull(response.Body, out[:int(response.ContentLength):int(response.ContentLength)])
	if err != nil {
		clear(out[:n])
		return 0, err
	}
	if err = call.Err(); err != nil {
		clear(out[:n])
		return 0, err
	}
	return n, nil
}

type headerReader struct {
	reader    io.Reader
	remaining int64
	active    bool
}

func (r *headerReader) Read(out []byte) (int, error) {
	if r.active {
		if r.remaining <= 0 {
			return 0, ErrResponse
		}
		if int64(len(out)) > r.remaining {
			out = out[:int(r.remaining)]
		}
	}
	n, err := r.reader.Read(out)
	if r.active {
		r.remaining -= int64(n)
	}
	return n, err
}

// Close fences future calls and wakes the one original physical read. Retire
// only succeeds after that call and its cancellation observer actually exit.
func (p *HTTPSBootstrapProvider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.stop)
	}
	p.cleanupLocked()
}

func (p *HTTPSBootstrapProvider) cleanupLocked() {
	if p.closed && !p.busy && !p.complete {
		p.complete = true
		close(p.done)
	}
}

func (p *HTTPSBootstrapProvider) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *HTTPSBootstrapProvider) Retire() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return nil
	}
	if !p.closed || p.busy {
		return ErrBusy
	}
	p.config, p.base, p.tls = HTTPSBootstrapConfig{}, url.URL{}, nil
	p.reservation.Release()
	p.dependencies.Release()
	p.reservation, p.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
	p.retired = true
	return nil
}
