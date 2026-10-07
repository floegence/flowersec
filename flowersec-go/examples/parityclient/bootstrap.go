package parityclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

func (c *Client) installNamespace(ctx context.Context, config Configuration) error {
	registryConfig := fs.VerificationNamespacesConfig{Continuity: fs.OnlineBootstrap, Entries: 1, RuntimeBytes: 65536}
	ref, err := c.reserve(fs.VerificationNamespacesCharge(registryConfig))
	if err != nil {
		return err
	}
	c.verification, err = fs.NewVerificationNamespaces(registryConfig, ref)
	ref.Release()
	if err != nil {
		return err
	}
	trustLimits := fs.NamespaceTrustLimits{Configurations: 4, ConfigBytes: 32768, MapNodes: 8192, RuntimeBytes: 65536}
	ref, err = c.reserve(fs.NamespaceTrustCharge(trustLimits))
	if err != nil {
		return err
	}
	borrow, err := c.dependencies.Borrow()
	if err != nil {
		ref.Release()
		return err
	}
	c.trust, err = fs.NewNamespaceTrustAnchor(config.Namespace, trustLimits, c.clock, ref, borrow)
	ref.Release()
	borrow.Release()
	if err != nil {
		return err
	}
	if err = c.verification.Register(c.trust); err != nil {
		return err
	}
	provider, err := newBootstrapProvider(config.BootstrapURL, config.Namespace, config.TLSRoots, c.clock)
	if err != nil {
		return err
	}
	defer provider.close()
	limits := fs.NamespaceBootstrapLimits{
		ResponseBytes: 32768, ResponseNodes: 8192, StateBytes: 4096,
		DurationMS: 4000, FetchDurationMS: 4000, FetchAttempts: 1, Subscribers: 8, RuntimeBytes: 65536,
		Provider: fs.ResourceVector{fs.SDKBytes: 262144, fs.ProviderBytes: 4 << 20,
			fs.Items: 1, fs.Tasks: 1, fs.Timers: 1, fs.Connections: 1, fs.TLSHandshakes: 1, fs.NativeHandles: 2},
	}
	allocation := fs.NamespaceAllocation{Root: c.root}
	for i := range allocation.Owners {
		allocation.Owners[i] = c.nextOwner()
	}
	ref, err = c.reserve(fs.NamespaceBootstrapCharge(limits))
	if err != nil {
		return err
	}
	c.bootstrap, err = fs.NewNamespaceOnlineBootstrap(c.lifetime, c.trust, limits, allocation, ref)
	ref.Release()
	if err != nil {
		return err
	}
	c.namespace, err = c.bootstrap.Run(ctx, provider)
	return err
}

// bootstrapProvider adapts the application's independently configured HTTPS
// authority endpoint. It uses one synchronous connection and joins its cancel
// callback before returning; it retains no HTTP pool or provider goroutine.
type bootstrapProvider struct {
	endpoint *url.URL
	address  netip.AddrPort
	root     fs.NamespaceTrustRoot
	tls      *tls.Config
	state    []byte
}

func newBootstrapProvider(endpoint string, root fs.NamespaceTrustRoot, roots *x509.CertPool, clock *fs.Clock) (*bootstrapProvider, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("bootstrap endpoint must be independently configured HTTPS")
	}
	address, err := numericAddress(u.Hostname(), u.Port())
	if err != nil {
		return nil, err
	}
	return &bootstrapProvider{endpoint: u, address: address, root: root,
		tls: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots,
			ServerName: u.Hostname(), NextProtos: []string{"http/1.1"},
			Time: func() time.Time {
				now, err := clock.Sample()
				if err != nil || now.LowerMS > math.MaxInt64 {
					return time.UnixMilli(0)
				}
				return time.UnixMilli(int64(now.LowerMS))
			},
			VerifyConnection: func(connection tls.ConnectionState) error {
				now, err := clock.Sample()
				if err != nil {
					return err
				}
				if now.UpperMS > math.MaxInt64 {
					return errors.New("qualified TLS time is outside its supported range")
				}
				lower, upper := time.UnixMilli(int64(now.LowerMS)), time.UnixMilli(int64(now.UpperMS))
				for _, chain := range connection.VerifiedChains {
					valid := len(chain) != 0
					for _, certificate := range chain {
						if lower.Before(certificate.NotBefore) || !upper.Before(certificate.NotAfter) {
							valid = false
							break
						}
					}
					if valid {
						return nil
					}
				}
				return errors.New("bootstrap certificate chain does not cover the complete qualified time interval")
			}}}, nil
}

func numericAddress(host, portText string) (netip.AddrPort, error) {
	if host == "localhost" {
		host = "127.0.0.1"
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.AddrPort{}, errors.New("example requires an explicit numeric endpoint or fixed localhost mapping")
	}
	if portText == "" {
		portText = "443"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("endpoint port is invalid")
	}
	return netip.AddrPortFrom(address, uint16(port)), nil
}

func (p *bootstrapProvider) Query(ctx context.Context, request fs.NamespaceBootstrapRequest, output []byte) (int, error) {
	if request.Tenant != p.root.Tenant || request.Authority != p.root.Authority {
		return 0, errors.New("bootstrap request does not match independently pinned namespace")
	}
	wire, err := json.Marshal(struct {
		Tenant    string `json:"tenant"`
		Authority string `json:"authority"`
		Nonce     []byte `json:"nonce"`
	}{request.Tenant, request.Authority, request.Nonce[:]})
	if err != nil {
		return 0, err
	}
	data, err := p.exchange(ctx, wire)
	if err != nil {
		return 0, err
	}
	defer clear(data)
	var reply struct {
		Response []byte `json:"response"`
		State    []byte `json:"state"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&reply); err != nil {
		return 0, err
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return 0, errors.New("bootstrap reply has trailing data")
	}
	if len(reply.Response) == 0 || len(reply.Response) > len(output) || len(reply.State) == 0 || len(reply.State) > 4096 {
		return 0, errors.New("bootstrap reply exceeds the admitted response or state bound")
	}
	p.state = append(p.state[:0], reply.State...)
	return copy(output, reply.Response), nil
}

func (p *bootstrapProvider) Fetch(ctx context.Context, content fs.NamespaceContent, output []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(p.state) != int(content.EncodedBytes) || len(p.state) > len(output) {
		return 0, errors.New("bootstrap state length mismatch")
	}
	// The original SDK namespace owner checks the requested content digest.
	return copy(output, p.state), nil
}

func (p *bootstrapProvider) close() { clear(p.state); p.state = nil }

func (p *bootstrapProvider) exchange(ctx context.Context, wire []byte) (data []byte, err error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address.String())
	if err != nil {
		return nil, err
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = connection.Close(); close(canceled) })
	defer func() {
		closeErr := connection.Close()
		if !stop() {
			<-canceled
		}
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	if cap, ok := ctx.Deadline(); ok && cap.Before(deadline) {
		deadline = cap
	}
	if err = connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	secure := tls.Client(connection, p.tls.Clone())
	if err = secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	if err = request.Write(secure); err != nil {
		return nil, err
	}
	// Bound headers, framing and payload together before the HTTP parser. The
	// payload has its own tighter bound and redirects are never followed.
	reader := bufio.NewReaderSize(io.LimitReader(secure, 65536+8192+1), 4096)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, response.Body.Close()) }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("bootstrap authority refused the bounded uncompressed reply")
	}
	if response.ContentLength == 0 || response.ContentLength > 65536 {
		return nil, errors.New("bootstrap reply exceeds its admitted content length")
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 65536 || response.ContentLength >= 0 && int64(len(data)) != response.ContentLength {
		return nil, errors.New("bootstrap reply length mismatch")
	}
	return data, nil
}
