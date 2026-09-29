package flowersec

import (
	"encoding/binary"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

var proxyHeaderName = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

var proxyForbiddenHeaders = map[string]struct{}{
	"authorization": {}, "connection": {}, "host": {}, "keep-alive": {},
	"proxy-authorization": {}, "proxy-authenticate": {}, "proxy-connection": {}, "te": {}, "trailer": {}, "set-cookie": {}, "transfer-encoding": {}, "upgrade": {},
}

var proxyBaseRequestHeaders = map[string]struct{}{
	"accept": {}, "accept-language": {}, "content-type": {}, "if-match": {}, "if-none-match": {}, "range": {},
}

var proxyBaseResponseHeaders = map[string]struct{}{
	"accept-ranges": {}, "cache-control": {}, "content-disposition": {}, "content-encoding": {}, "content-language": {},
	"content-length": {}, "content-range": {}, "content-type": {}, "etag": {}, "expires": {}, "last-modified": {}, "location": {},
}

type proxyRequestHeaderResult struct {
	Header        http.Header
	ContentLength int64
	HasLength     bool
	Connection    map[string]struct{}
}

type proxyHeader = protocolv4.ProxyHeader
type proxyWireError = protocolv4.ProxyError
type proxyHTTPRequest = protocolv4.ProxyHTTPRequest
type proxyHTTPResponse = protocolv4.ProxyHTTPResponse
type proxyWebSocketOpen = protocolv4.ProxyWebSocketOpen
type proxyWebSocketResponse = protocolv4.ProxyWebSocketResponse

func normalizeProxyHeaderSet(values []string, allowSetCookie ...bool) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, raw := range values {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !proxyHeaderName.MatchString(name) {
			return nil, ErrInvalidProxyServer
		}
		if _, forbidden := proxyForbiddenHeaders[name]; forbidden && !(name == "set-cookie" && len(allowSetCookie) > 0 && allowSetCookie[0]) {
			return nil, ErrInvalidProxyServer
		}
		result[name] = struct{}{}
	}
	return result, nil
}

func proxyHeaderAllowed(name string, base, extra map[string]struct{}) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if _, forbidden := proxyForbiddenHeaders[name]; forbidden && !(name == "set-cookie" && configHeaderAllowsSetCookie(extra)) {
		return false
	}
	_, baseAllowed := base[name]
	_, extraAllowed := extra[name]
	return (baseAllowed || extraAllowed) && proxyHeaderName.MatchString(name)
}

func configHeaderAllowsSetCookie(extra map[string]struct{}) bool {
	_, ok := extra["set-cookie"]
	return ok
}

type proxyHeaderFacts struct {
	length              int64
	hasLength, transfer bool
	connection          map[string]struct{}
}

func inspectProxyHeaders(input []proxyHeader) (proxyHeaderFacts, error) {
	facts := proxyHeaderFacts{connection: make(map[string]struct{})}
	singletons := make(map[string]string)
	for _, h := range input {
		name := strings.ToLower(h.Name)
		if !protocolv4.ProxyASCIIToken(name) || !protocolv4.ProxyFieldOctets(h.Value) {
			return facts, ErrInvalidProxyServer
		}
		switch name {
		case "content-length":
			for _, part := range strings.Split(h.Value, ",") {
				part = strings.Trim(part, " \t")
				if part == "" {
					return facts, ErrInvalidProxyServer
				}
				for _, b := range []byte(part) {
					if b < '0' || b > '9' {
						return facts, ErrInvalidProxyServer
					}
				}
				length, err := strconv.ParseInt(part, 10, 64)
				if err != nil || facts.hasLength && facts.length != length {
					return facts, ErrInvalidProxyServer
				}
				facts.length, facts.hasLength = length, true
			}
		case "transfer-encoding":
			facts.transfer = true
		case "connection":
			for _, token := range strings.Split(h.Value, ",") {
				token = strings.ToLower(strings.Trim(token, " \t"))
				if !protocolv4.ProxyASCIIToken(token) {
					return facts, ErrInvalidProxyServer
				}
				facts.connection[token] = struct{}{}
			}
		}
		switch name {
		case "host", "origin", "authorization", "proxy-authorization", "content-type", "content-range", "etag", "last-modified", "location":
			value := strings.Trim(h.Value, " \t")
			if prior, ok := singletons[name]; ok && prior != value {
				return facts, ErrInvalidProxyServer
			}
			singletons[name] = value
		}
	}
	if facts.transfer && facts.hasLength {
		return facts, ErrInvalidProxyServer
	}
	return facts, nil
}
func proxyRequestHeaders(input []proxyHeader, config proxyServerConfig) (proxyRequestHeaderResult, error) {
	facts, err := inspectProxyHeaders(input)
	if err != nil || facts.transfer {
		return proxyRequestHeaderResult{}, ErrInvalidProxyServer
	}
	result := make(http.Header)
	for _, h := range input {
		name := strings.ToLower(h.Name)
		if name == "host" {
			return proxyRequestHeaderResult{}, ErrInvalidProxyServer
		}
		if _, hop := facts.connection[name]; hop || name == "content-length" || !proxyHeaderAllowed(name, proxyBaseRequestHeaders, config.requestHeaders) {
			continue
		}
		value := h.Value
		if name == "cookie" {
			value = filterProxyCookies(value, config)
			if value == "" {
				continue
			}
		}
		result.Add(name, value)
	}
	return proxyRequestHeaderResult{Header: result, ContentLength: facts.length, HasLength: facts.hasLength, Connection: facts.connection}, nil
}
func proxyNativeHeaders(input http.Header) []proxyHeader {
	// net/http preserves each name's original value order. Its public Header map
	// does not retain inter-name arrival order; use a deterministic projection.
	names := make([]string, 0, len(input))
	for name := range input {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]proxyHeader, 0, len(input))
	for _, name := range names {
		for _, value := range input[name] {
			result = append(result, proxyHeader{Name: strings.ToLower(name), Value: value})
		}
	}
	return result
}
func proxyResponseHeaders(input http.Header, config proxyServerConfig) []proxyHeader {
	fields := proxyNativeHeaders(input)
	facts, err := inspectProxyHeaders(fields)
	if err != nil {
		return nil
	}
	result := make([]proxyHeader, 0, len(fields))
	lengthAdded := false
	for _, h := range fields {
		if _, hop := facts.connection[h.Name]; hop || !proxyHeaderAllowed(h.Name, proxyBaseResponseHeaders, config.responseHeaders) {
			continue
		}
		if _, blocked := config.blockedResponses[h.Name]; blocked {
			continue
		}
		if h.Name == "content-length" {
			if lengthAdded {
				continue
			}
			lengthAdded = true
			h.Value = strconv.FormatInt(facts.length, 10)
		}
		result = append(result, h)
	}
	return result
}
func proxyWebSocketHeaders(input []proxyHeader, config proxyServerConfig) (http.Header, error) {
	facts, err := inspectProxyHeaders(input)
	if err != nil || facts.transfer || facts.hasLength && facts.length != 0 {
		return nil, ErrInvalidProxyServer
	}
	base := map[string]struct{}{"sec-websocket-protocol": {}}
	result := make(http.Header)
	for _, h := range input {
		name := strings.ToLower(h.Name)
		if _, hop := facts.connection[name]; hop {
			continue
		}
		if proxyHeaderAllowed(name, base, config.webSocketHeaders) {
			result.Add(name, h.Value)
		}
	}
	return result, nil
}

func filterProxyCookies(value string, config proxyServerConfig) string {
	parts := strings.Split(value, ";")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		name, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, forbidden := config.forbiddenCookies[name]; forbidden {
			continue
		}
		blocked := false
		for _, prefix := range config.forbiddenPrefixes {
			if strings.HasPrefix(name, prefix) {
				blocked = true
				break
			}
		}
		if !blocked {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "; ")
}

func readProxyMetadata(reader io.Reader, maximum int, target any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return err
	}
	length := uint64(binary.BigEndian.Uint32(prefix[:]))
	if length == 0 || length > uint64(maximum) || length > uint64(protocolv4.ProxyMetadataLimit()) {
		return ErrInvalidProxyServer
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	return protocolv4.DecodeProxyMetadata(payload, target)
}
func writeProxyMetadata(writer io.Writer, value any) error {
	payload, err := protocolv4.EncodeProxyMetadata(value)
	if err != nil {
		return err
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if err := writeProxyAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeProxyAll(writer, payload)
}
func writeProxyAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if n < 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func proxyValidateTrailers(headers []proxyHeader) error {
	if _, err := inspectProxyHeaders(headers); err != nil {
		return err
	}
	for _, h := range headers {
		if !protocolv4.ProxyASCIIToken(h.Name) || !protocolv4.ProxyFieldOctets(h.Value) {
			return ErrInvalidProxyServer
		}
		if _, bad := proxyForbiddenHeaders[h.Name]; bad {
			return ErrInvalidProxyServer
		}
		switch h.Name {
		case "content-length", "content-encoding", "content-range", "content-type", "host", "cookie", "origin", "location", "authorization", "www-authenticate":
			return ErrInvalidProxyServer
		}
	}
	return nil
}

func readProxyChunk(reader io.Reader, maximum int, total *int64, bodyMaximum int64) ([]byte, bool, error) {
	return readProxyBodyChunk(reader, maximum, total, bodyMaximum, false)
}
func readProxyBodyChunk(reader io.Reader, maximum int, total *int64, bodyMaximum int64, request bool) ([]byte, bool, error) {
	payload, _, done, err := readProxyBodyPart(reader, maximum, total, bodyMaximum, protocolv4.ProxyMetadataLimit())
	return payload, done, err
}

func readProxyBodyPart(reader io.Reader, maximum int, total *int64, bodyMaximum int64, metadataMaximum int) ([]byte, []proxyHeader, bool, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, nil, false, err
	}
	length := int64(binary.BigEndian.Uint32(header[:]))
	if length == 0 {
		var terminal protocolv4.ProxyBodyEnd
		if err := readProxyMetadata(reader, metadataMaximum, &terminal); err != nil {
			return nil, nil, false, err
		}
		return nil, terminal.Trailers, true, proxyValidateTrailers(terminal.Trailers)
	}
	if length > int64(maximum) || *total+length > bodyMaximum {
		return nil, nil, false, ErrInvalidProxyServer
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, nil, false, err
	}
	*total += length
	return payload, nil, false, nil
}

func writeProxyChunk(writer io.Writer, payload []byte, maximum int, total *int64, bodyMaximum int64) error {
	if len(payload) > maximum || *total+int64(len(payload)) > bodyMaximum {
		return ErrInvalidProxyServer
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeProxyAll(writer, header[:]); err != nil {
		return err
	}
	if len(payload) != 0 {
		if err := writeProxyAll(writer, payload); err != nil {
			return err
		}
	}
	*total += int64(len(payload))
	return nil
}

func writeProxyTerminator(writer io.Writer) error { return writeProxyBodyEnd(writer, nil) }
func writeProxyBodyEnd(writer io.Writer, trailers []proxyHeader) error {
	if err := proxyValidateTrailers(trailers); err != nil {
		return err
	}
	var prefix [4]byte
	if err := writeProxyAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeProxyMetadata(writer, protocolv4.ProxyBodyEnd{Version: proxyWireVersion, Trailers: trailers})
}

func writeProxyWebSocketFrame(writer io.Writer, operation byte, payload []byte, maximum int) error {
	if len(payload) > maximum {
		return ErrInvalidProxyServer
	}
	header := make([]byte, 5)
	header[0] = operation
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if err := writeProxyAll(writer, header); err != nil {
		return err
	}
	return writeProxyAll(writer, payload)
}

func readProxyWebSocketFrame(reader io.Reader, maximum int) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:]))
	if length > maximum {
		return 0, nil, ErrInvalidProxyServer
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(reader, payload)
	return header[0], payload, err
}

func proxyStableError(code string) *proxyWireError {
	return &proxyWireError{Code: code, Message: "proxy operation failed"}
}
