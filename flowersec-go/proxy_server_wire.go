package flowersec

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	internaljsonframe "github.com/floegence/flowersec/flowersec-go/v3/internal/framing/jsonframe"
)

var proxyHeaderName = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

var proxyForbiddenHeaders = map[string]struct{}{
	"authorization": {}, "connection": {}, "host": {}, "keep-alive": {},
	"proxy-authorization": {}, "set-cookie": {}, "transfer-encoding": {}, "upgrade": {},
}

var proxyBaseRequestHeaders = map[string]struct{}{
	"accept": {}, "accept-language": {}, "content-type": {}, "if-match": {}, "if-none-match": {}, "range": {},
}

var proxyBaseResponseHeaders = map[string]struct{}{
	"accept-ranges": {}, "cache-control": {}, "content-disposition": {}, "content-language": {},
	"content-range": {}, "content-type": {}, "etag": {}, "expires": {}, "last-modified": {}, "location": {},
}

type proxyHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type proxyWireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type proxyHTTPRequest struct {
	Version        int           `json:"v"`
	RequestID      string        `json:"request_id"`
	Method         string        `json:"method"`
	Path           string        `json:"path"`
	Headers        []proxyHeader `json:"headers"`
	ExternalOrigin string        `json:"external_origin,omitempty"`
	TimeoutMS      int64         `json:"timeout_ms,omitempty"`
}

type proxyHTTPResponse struct {
	Version   int             `json:"v"`
	RequestID string          `json:"request_id"`
	OK        bool            `json:"ok"`
	Status    int             `json:"status,omitempty"`
	Headers   []proxyHeader   `json:"headers,omitempty"`
	Error     *proxyWireError `json:"error,omitempty"`
}

type proxyWebSocketOpen struct {
	Version int           `json:"v"`
	ConnID  string        `json:"conn_id"`
	Path    string        `json:"path"`
	Headers []proxyHeader `json:"headers"`
}

type proxyWebSocketResponse struct {
	Version  int             `json:"v"`
	ConnID   string          `json:"conn_id"`
	OK       bool            `json:"ok"`
	Protocol string          `json:"protocol,omitempty"`
	Error    *proxyWireError `json:"error,omitempty"`
}

func normalizeProxyHeaderSet(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, raw := range values {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !proxyHeaderName.MatchString(name) {
			return nil, ErrInvalidProxyServer
		}
		if _, forbidden := proxyForbiddenHeaders[name]; forbidden {
			return nil, ErrInvalidProxyServer
		}
		result[name] = struct{}{}
	}
	return result, nil
}

func proxyHeaderAllowed(name string, base, extra map[string]struct{}) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if _, forbidden := proxyForbiddenHeaders[name]; forbidden {
		return false
	}
	_, baseAllowed := base[name]
	_, extraAllowed := extra[name]
	return (baseAllowed || extraAllowed) && proxyHeaderName.MatchString(name)
}

func proxyRequestHeaders(input []proxyHeader, config proxyServerConfig) http.Header {
	result := make(http.Header)
	for _, header := range input {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		if !proxyHeaderAllowed(name, proxyBaseRequestHeaders, config.requestHeaders) || strings.ContainsAny(header.Value, "\r\n") {
			continue
		}
		value := header.Value
		if name == "cookie" {
			value = filterProxyCookies(value, config)
			if value == "" {
				continue
			}
		}
		result.Add(name, value)
	}
	return result
}

func proxyResponseHeaders(input http.Header, config proxyServerConfig) []proxyHeader {
	result := make([]proxyHeader, 0)
	for name, values := range input {
		lower := strings.ToLower(strings.TrimSpace(name))
		if !proxyHeaderAllowed(lower, proxyBaseResponseHeaders, config.responseHeaders) {
			continue
		}
		if _, blocked := config.blockedResponses[lower]; blocked {
			continue
		}
		for _, value := range values {
			if !strings.ContainsAny(value, "\r\n") {
				result = append(result, proxyHeader{Name: lower, Value: value})
			}
		}
	}
	return result
}

func proxyWebSocketHeaders(input []proxyHeader, config proxyServerConfig) http.Header {
	base := map[string]struct{}{"sec-websocket-protocol": {}}
	result := make(http.Header)
	for _, header := range input {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		if proxyHeaderAllowed(name, base, config.webSocketHeaders) && !strings.ContainsAny(header.Value, "\r\n") {
			result.Add(name, header.Value)
		}
	}
	return result
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

func readProxyJSON(reader io.Reader, maximum int, target any) error {
	payload, err := internaljsonframe.ReadJSONFrame(reader, maximum)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidProxyServer
	}
	return nil
}

func writeProxyJSON(writer io.Writer, value any) error {
	return internaljsonframe.WriteJSONFrame(writer, value)
}

func readProxyChunk(reader io.Reader, maximum int, total *int64, bodyMaximum int64) ([]byte, bool, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, false, err
	}
	length := int64(binary.BigEndian.Uint32(header[:]))
	if length == 0 {
		return nil, true, nil
	}
	if length > int64(maximum) || *total+length > bodyMaximum {
		return nil, false, ErrInvalidProxyServer
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, false, err
	}
	*total += length
	return payload, false, nil
}

func writeProxyChunk(writer io.Writer, payload []byte, maximum int, total *int64, bodyMaximum int64) error {
	if len(payload) > maximum || *total+int64(len(payload)) > bodyMaximum {
		return ErrInvalidProxyServer
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	if len(payload) != 0 {
		if _, err := writer.Write(payload); err != nil {
			return err
		}
	}
	*total += int64(len(payload))
	return nil
}

func writeProxyTerminator(writer io.Writer) error {
	var header [4]byte
	_, err := writer.Write(header[:])
	return err
}

func writeProxyWebSocketFrame(writer io.Writer, operation byte, payload []byte, maximum int) error {
	if len(payload) > maximum {
		return ErrInvalidProxyServer
	}
	header := make([]byte, 5)
	header[0] = operation
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
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
