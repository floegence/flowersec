package protocolv4

import (
	"encoding/json"
	"strings"
)

// Proxy messages are application Stream payloads. Header strings carry HTTP
// octets, not UTF-8 text. Only this canonical schema is accepted on the wire.
type ProxyHeader struct{ Name, Value string }
type ProxyError struct{ Code, Message string }
type ProxyHTTPRequest struct {
	Version                 int
	RequestID, Method, Path string
	Headers                 []ProxyHeader
	ExternalOrigin          string
	TimeoutMS               int64
}
type ProxyHTTPResponse struct {
	Version   int
	RequestID string
	OK        bool
	Status    int
	Headers   []ProxyHeader
	Error     *ProxyError
}
type ProxyWebSocketOpen struct {
	Version      int
	ConnID, Path string
	Headers      []ProxyHeader
}
type ProxyWebSocketResponse struct {
	Version  int
	ConnID   string
	OK       bool
	Protocol string
	Error    *ProxyError
}
type ProxyBodyEnd struct {
	Version  int
	Trailers []ProxyHeader
}

type proxyApplicationRegistry struct {
	Version  int `json:"version"`
	Metadata int `json:"max_metadata_bytes"`
	Fields   int `json:"max_field_count"`
}

var proxyApplication = func() proxyApplicationRegistry {
	var r proxyApplicationRegistry
	if err := json.Unmarshal([]byte(ProxyApplicationRegistryJSON), &r); err != nil {
		panic(err)
	}
	return r
}()

func ProxyApplicationVersion() int { return proxyApplication.Version }
func ProxyMetadataLimit() int      { return proxyApplication.Metadata }

func ProxyFieldOctets(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '\t' && (value[i] < 32 || value[i] == 127) {
			return false
		}
	}
	return true
}
func ProxyASCIIToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			continue
		}
		return false
	}
	return true
}
func proxyASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}
func proxySchema(value any) string {
	switch value.(type) {
	case ProxyHTTPRequest, *ProxyHTTPRequest:
		return "ProxyHTTPRequest"
	case ProxyHTTPResponse, *ProxyHTTPResponse:
		return "ProxyHTTPResponse"
	case ProxyWebSocketOpen, *ProxyWebSocketOpen:
		return "ProxyWebSocketOpen"
	case ProxyWebSocketResponse, *ProxyWebSocketResponse:
		return "ProxyWebSocketResponse"
	case ProxyBodyEnd, *ProxyBodyEnd:
		return "ProxyBodyEnd"
	}
	return ""
}

// DecodeProxyMetadata uses the existing canonical decoder. Its arena is bounded
// by the original wire size and field count, and no normalization workspace is
// allocated for these byte-only application maps.
func DecodeProxyMetadata(wire []byte, output any) error {
	schema := proxySchema(output)
	if schema == "" || len(wire) == 0 || len(wire) > proxyApplication.Metadata {
		return CBORFailure("proxy_metadata")
	}
	nodes := min(len(wire), 5*proxyApplication.Fields+32)
	d, err := newDecoder(len(wire), nodes, 0)
	if err != nil {
		return err
	}
	doc, err := d.DecodeMap(wire, schema, DecodeContext{Limits: map[string]uint64{"max_proxy_fields": uint64(proxyApplication.Fields)}})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	getBytes := func(name string) string { b, _ := root.Named(schema, name).ByteString(); return string(b) }
	getUint := func(name string) uint64 { n, _ := root.Named(schema, name).Uint(); return n }
	getHeaders := func(name string) ([]ProxyHeader, error) {
		v := root.Named(schema, name)
		if !v.valid() {
			return nil, nil
		}
		result := make([]ProxyHeader, 0, v.Len())
		for index := d.nodes[v.index].first; index >= 0; index = d.nodes[index].next {
			item := Value{doc, index}
			n, _ := item.Named("ProxyField", "name").ByteString()
			value, _ := item.Named("ProxyField", "value").ByteString()
			h := ProxyHeader{string(n), string(value)}
			if !ProxyASCIIToken(h.Name) || h.Name != strings.ToLower(h.Name) || !ProxyFieldOctets(h.Value) {
				return nil, CBORFailure("proxy_header")
			}
			result = append(result, h)
		}
		return result, nil
	}
	getError := func() (*ProxyError, error) {
		v := root.Named(schema, "error")
		if !v.valid() {
			return nil, nil
		}
		code, _ := v.Named("ProxyError", "code").ByteString()
		message, _ := v.Named("ProxyError", "message").ByteString()
		if !proxyASCII(string(code)) || !proxyASCII(string(message)) {
			return nil, CBORFailure("proxy_error")
		}
		return &ProxyError{string(code), string(message)}, nil
	}
	for _, name := range []string{"request_id", "method", "path", "external_origin", "conn_id", "protocol"} {
		if !proxyASCII(getBytes(name)) {
			return CBORFailure("proxy_ascii")
		}
	}
	version := int(getUint("version"))
	if v, ok := output.(*ProxyBodyEnd); ok {
		h, e := getHeaders("trailers")
		if e != nil {
			return e
		}
		*v = ProxyBodyEnd{version, h}
		return nil
	}
	h, err := getHeaders("headers")
	if err != nil {
		return err
	}
	switch v := output.(type) {
	case *ProxyHTTPRequest:
		if !ProxyASCIIToken(getBytes("method")) {
			return CBORFailure("proxy_method")
		}
		*v = ProxyHTTPRequest{version, getBytes("request_id"), getBytes("method"), getBytes("path"), h, getBytes("external_origin"), int64(getUint("timeout_ms"))}
	case *ProxyWebSocketOpen:
		*v = ProxyWebSocketOpen{version, getBytes("conn_id"), getBytes("path"), h}
	case *ProxyHTTPResponse:
		ok, _ := root.Named(schema, "ok").Bool()
		e, err := getError()
		if err != nil {
			return err
		}
		if ok && (e != nil || !root.Named(schema, "status").valid() || !root.Named(schema, "headers").valid()) || !ok && (e == nil || root.Named(schema, "status").valid() || root.Named(schema, "headers").valid()) {
			return CBORFailure("proxy_response_variant")
		}
		*v = ProxyHTTPResponse{version, getBytes("request_id"), ok, int(getUint("status")), h, e}
	case *ProxyWebSocketResponse:
		ok, _ := root.Named(schema, "ok").Bool()
		e, err := getError()
		if err != nil {
			return err
		}
		if ok && (e != nil || !root.Named(schema, "protocol").valid()) || !ok && (e == nil || root.Named(schema, "protocol").valid()) {
			return CBORFailure("proxy_response_variant")
		}
		*v = ProxyWebSocketResponse{version, getBytes("conn_id"), ok, getBytes("protocol"), e}
	default:
		return CBORFailure("proxy_output")
	}
	return nil
}

func EncodeProxyMetadata(value any) ([]byte, error) {
	schema := proxySchema(value)
	fields := []Field{{Name: "version", Number: uint64(proxyApplication.Version)}}
	invalid := false
	add := func(name, value string) {
		if !proxyASCII(value) || value == "" && (name == "request_id" || name == "conn_id" || name == "method" || name == "path") {
			invalid = true
		}
		fields = append(fields, Field{Name: name, Kind: ByteString, Bytes: []byte(value)})
	}
	var headers []ProxyHeader
	var problem *ProxyError
	fieldName := "headers"
	switch v := value.(type) {
	case ProxyHTTPRequest:
		if v.Version != proxyApplication.Version || v.TimeoutMS < 0 || v.TimeoutMS > 300000 || !ProxyASCIIToken(v.Method) {
			return nil, CBORFailure("proxy_version")
		}
		add("request_id", v.RequestID)
		add("method", v.Method)
		add("path", v.Path)
		headers = v.Headers
		if v.ExternalOrigin != "" {
			add("external_origin", v.ExternalOrigin)
		}
		if v.TimeoutMS != 0 {
			fields = append(fields, Field{Name: "timeout_ms", Number: uint64(v.TimeoutMS)})
		}
	case ProxyHTTPResponse:
		if v.OK && (v.Status < 200 || v.Status > 599 || v.Error != nil) || !v.OK && (v.Error == nil || v.Status != 0 || len(v.Headers) != 0) {
			return nil, CBORFailure("proxy_response_variant")
		}
		if v.Version != proxyApplication.Version {
			return nil, CBORFailure("proxy_version")
		}
		add("request_id", v.RequestID)
		fields = append(fields, Field{Name: "ok", Kind: Boolean})
		if v.OK {
			fields[len(fields)-1].Number = 1
			fields = append(fields, Field{Name: "status", Number: uint64(v.Status)})
			headers = v.Headers
		} else {
			fieldName = ""
		}
		problem = v.Error
	case ProxyWebSocketOpen:
		if v.Version != proxyApplication.Version {
			return nil, CBORFailure("proxy_version")
		}
		add("conn_id", v.ConnID)
		add("path", v.Path)
		headers = v.Headers
	case ProxyWebSocketResponse:
		if v.OK && v.Error != nil || !v.OK && (v.Error == nil || v.Protocol != "") {
			return nil, CBORFailure("proxy_response_variant")
		}
		if v.Version != proxyApplication.Version {
			return nil, CBORFailure("proxy_version")
		}
		add("conn_id", v.ConnID)
		fields = append(fields, Field{Name: "ok", Kind: Boolean})
		if v.OK {
			fields[len(fields)-1].Number = 1
			add("protocol", v.Protocol)
		}
		fieldName = ""
		problem = v.Error
	case ProxyBodyEnd:
		if v.Version != proxyApplication.Version {
			return nil, CBORFailure("proxy_version")
		}
		fieldName = "trailers"
		headers = v.Trailers
	default:
		return nil, CBORFailure("proxy_input")
	}
	if invalid {
		return nil, CBORFailure("proxy_ascii")
	}
	if problem != nil && (!proxyASCII(problem.Code) || problem.Code == "" || !proxyASCII(problem.Message) || problem.Message == "") {
		return nil, CBORFailure("proxy_error")
	}
	if len(headers) > proxyApplication.Fields {
		return nil, CBORFailure("proxy_header_count")
	}
	// Encode nested values directly into a single bounded workspace. The final
	// map has one additional bounded buffer; neither grows on peer claims.
	width := func(n int) int {
		switch {
		case n < 24:
			return 1
		case n <= 255:
			return 2
		case n <= 65535:
			return 3
		default:
			return 5
		}
	}
	workspace := 0
	if fieldName != "" {
		workspace = width(len(headers))
	}
	for _, h := range headers {
		if len(h.Name) > proxyApplication.Metadata || len(h.Value) > proxyApplication.Metadata {
			return nil, CBORFailure("encoder_capacity")
		}
		workspace += 3 + width(len(h.Name)) + len(h.Name) + width(len(h.Value)) + len(h.Value)
		if workspace > proxyApplication.Metadata {
			return nil, CBORFailure("encoder_capacity")
		}
	}
	if problem != nil {
		workspace += 3 + width(len(problem.Code)) + len(problem.Code) + width(len(problem.Message)) + len(problem.Message)
	}
	if workspace > proxyApplication.Metadata {
		return nil, CBORFailure("encoder_capacity")
	}
	work := make([]byte, workspace)
	at := 0
	if fieldName != "" {
		n, err := cborHead(work, 4, uint64(len(headers)))
		if err != nil {
			return nil, err
		}
		at = n
		for _, h := range headers {
			name := strings.ToLower(h.Name)
			if !ProxyASCIIToken(name) || !ProxyFieldOctets(h.Value) {
				return nil, CBORFailure("proxy_header")
			}
			encoded, err := EncodeMap(work[at:], "ProxyField", []Field{{Name: "name", Kind: ByteString, Bytes: []byte(name)}, {Name: "value", Kind: ByteString, Bytes: []byte(h.Value)}})
			if err != nil {
				return nil, err
			}
			at += len(encoded)
		}
		fields = append(fields, Field{Name: fieldName, Kind: EncodedArray, Bytes: work[:at]})
	}
	if problem != nil {
		encoded, err := EncodeMap(work[at:], "ProxyError", []Field{{Name: "code", Kind: ByteString, Bytes: []byte(problem.Code)}, {Name: "message", Kind: ByteString, Bytes: []byte(problem.Message)}})
		if err != nil {
			return nil, err
		}
		fields = append(fields, Field{Name: "error", Kind: EncodedMap, Bytes: encoded})
	}
	sink := mapEncodingSink{measure: true}
	if err := processMap(&sink, schema, fields, ""); err != nil {
		return nil, err
	}
	if sink.offset > proxyApplication.Metadata {
		return nil, CBORFailure("encoder_capacity")
	}
	out, err := EncodeMap(make([]byte, sink.offset), schema, fields)
	if err != nil {
		return nil, err
	}
	return out, nil
}
