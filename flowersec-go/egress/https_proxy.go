// Package egress provides explicit outbound routes without changing peer trust.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidProxy    = errors.New("invalid HTTPS egress proxy")
	ErrProxyConnection = errors.New("HTTPS egress proxy connection failed")
)

// HTTPSProxyOptions separates proxy TLS identity from the destination's TLS
// policy. URL must be an HTTPS origin without credentials, queries or fragments.
type HTTPSProxyOptions struct {
	URL            string
	TLSConfig      *tls.Config
	ConnectTimeout time.Duration
}

// HTTPSProxy is an immutable explicit route. Every dial goes through this
// proxy; proxy failures never fall back to a direct connection or environment.
type HTTPSProxy struct {
	address string
	trust   *tls.Config
	timeout time.Duration
}

func (p *HTTPSProxy) String() string               { return "Flowersec.HTTPSProxy" }
func (p *HTTPSProxy) GoString() string             { return "egress.HTTPSProxy" }
func (p *HTTPSProxy) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Valid reports whether the proxy was successfully constructed.
func (p *HTTPSProxy) Valid() bool {
	return p != nil && p.trust != nil && p.address != "" && p.timeout > 0
}

func NewHTTPSProxy(options HTTPSProxyOptions) (*HTTPSProxy, error) {
	endpoint, err := url.Parse(options.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" || endpoint.Opaque != "" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" || options.ConnectTimeout < 0 {
		return nil, ErrInvalidProxy
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	if !validPort(port) {
		return nil, ErrInvalidProxy
	}
	trust := &tls.Config{}
	if options.TLSConfig != nil {
		trust = options.TLSConfig.Clone()
		if trust.InsecureSkipVerify || trust.ServerName != "" ||
			(trust.MinVersion != 0 && trust.MinVersion < tls.VersionTLS13) ||
			(trust.MaxVersion != 0 && trust.MaxVersion < tls.VersionTLS13) {
			return nil, ErrInvalidProxy
		}
		if trust.RootCAs != nil {
			trust.RootCAs = trust.RootCAs.Clone()
		}
		trust.Certificates = append([]tls.Certificate(nil), trust.Certificates...)
	}
	trust.MinVersion = tls.VersionTLS13
	trust.ServerName = endpoint.Hostname()
	trust.NextProtos = []string{"http/1.1"}
	timeout := options.ConnectTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	return &HTTPSProxy{address: net.JoinHostPort(endpoint.Hostname(), port), trust: trust, timeout: timeout}, nil
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}

// DialContext establishes an opaque TCP stream to address through CONNECT.
// Only the proxy address is resolved locally. The caller owns destination TLS.
func (p *HTTPSProxy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !p.Valid() || network != "tcp" {
		return nil, ErrInvalidProxy
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\t /\\@?#") || !validPort(port) {
		return nil, ErrInvalidProxy
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	dialer := tls.Dialer{Config: p.trust}
	conn, err := dialer.DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, proxyError(ctx)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, proxyError(ctx)
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
	defer stop()
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if err := request.Write(conn); err != nil {
		return nil, proxyError(ctx)
	}
	// Bound response-header memory while preserving any eagerly received stream
	// bytes. The limiter must not remain on the returned application stream.
	reader := bufio.NewReader(io.LimitReader(conn, 64<<10))
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, proxyError(ctx)
	}
	pending, err := reader.Peek(reader.Buffered())
	if err != nil {
		return nil, proxyError(ctx)
	}
	buffered := append([]byte(nil), pending...)
	if !stop() {
		<-closed
		return nil, proxyError(ctx)
	}
	if ctx.Err() != nil {
		return nil, proxyError(ctx)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, proxyError(ctx)
	}
	success = true
	return &bufferedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(buffered), conn)}, nil
}

func proxyError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrProxyConnection, err)
	}
	return ErrProxyConnection
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// HTTPTransport returns an independently owned transport using this route.
// Destination HTTPS verification stays enabled; no process proxy setting is read.
func (p *HTTPSProxy) HTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext:           p.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
