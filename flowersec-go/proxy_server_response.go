package flowersec

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// net/http removes Connection when it contains close, and normalizes transfer
// framing before returning Response. Capture the bounded original header block
// at the private plaintext connection entrance, before those facts disappear.
// The standard library remains the only body/chunk/trailer framing parser.
type proxyResponseConn struct {
	net.Conn
	mu                sync.Mutex
	maximum, consumed int
	buffer            []byte
	headers           http.Header
	armed, failed     bool
}

type proxyResponseTLSConn struct {
	*proxyResponseConn
	tls *tls.Conn
}

func (c *proxyResponseTLSConn) ConnectionState() tls.ConnectionState { return c.tls.ConnectionState() }

func (c *proxyResponseConn) arm() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || c.armed || c.headers != nil {
		return ErrInvalidProxyServer
	}
	c.armed, c.consumed = true, 0
	c.buffer = c.buffer[:0]
	return nil
}

func (c *proxyResponseConn) take() (http.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || c.armed || c.headers == nil {
		return nil, ErrInvalidProxyServer
	}
	headers := c.headers
	c.headers = nil
	return headers, nil
}

func (c *proxyResponseConn) Read(output []byte) (int, error) {
	n, err := c.Conn.Read(output)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, value := range output[:n] {
		if !c.armed {
			break
		}
		if c.consumed == c.maximum {
			c.failed = true
			return 0, ErrInvalidProxyServer
		}
		c.consumed++
		c.buffer = append(c.buffer, value)
		if !bytes.HasSuffix(c.buffer, []byte("\r\n\r\n")) {
			continue
		}
		status, headers, parseErr := proxyOriginalResponseHeaders(c.buffer)
		if parseErr != nil {
			c.failed = true
			return 0, parseErr
		}
		clear(c.buffer)
		c.buffer = c.buffer[:0]
		if status >= 100 && status < 200 && status != 101 {
			continue
		}
		c.headers, c.armed = headers, false
	}
	return n, err
}

func proxyOriginalResponseHeaders(block []byte) (int, http.Header, error) {
	lines := bytes.Split(block[:len(block)-4], []byte("\r\n"))
	if len(lines) == 0 || len(lines) > 65536 {
		return 0, nil, ErrInvalidProxyServer
	}
	version, rest, ok := strings.Cut(string(lines[0]), " ")
	if !ok || version != "HTTP/1.1" && version != "HTTP/1.0" {
		return 0, nil, ErrInvalidProxyServer
	}
	code, _, _ := strings.Cut(rest, " ")
	status, err := strconv.Atoi(code)
	if err != nil || len(code) != 3 || status < 100 || status > 599 {
		return 0, nil, ErrInvalidProxyServer
	}
	fields := make([]proxyHeader, 0, len(lines)-1)
	headers := make(http.Header, len(lines)-1)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(string(line), ":")
		if !ok || name == "" || strings.TrimSpace(name) != name {
			return 0, nil, ErrInvalidProxyServer
		}
		name = strings.ToLower(name)
		value = strings.Trim(value, " \t")
		fields = append(fields, proxyHeader{Name: name, Value: value})
		headers.Add(name, value)
	}
	if _, err := inspectProxyHeaders(fields); err != nil {
		return 0, nil, err
	}
	return status, headers, nil
}
