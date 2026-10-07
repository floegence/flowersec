package protocolv4

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Proxy messages are application Stream payloads. Header strings carry HTTP
// octets, not UTF-8 text. Only this canonical schema is accepted on the wire.
type ProxyHeader struct{ Name, Value string }
type ProxyError struct{ Code, Message string }
type ProxyHTTPRequest struct {
	Version                                       int
	RequestID, Method, Path                       string
	Headers                                       []ProxyHeader
	ExternalOrigin                                string
	TimeoutMS                                     int64
	CredentialContext, Credentials, RequestOrigin string
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
	Version                                       int
	ConnID, Path                                  string
	Headers                                       []ProxyHeader
	CredentialContext, Credentials, RequestOrigin string
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

type ProxyCredentialControlRequest struct {
	Version                          int
	OperationID                      string
	Action                           uint8
	SurfaceOwner                     string
	CredentialContext, ContentOrigin string
}
type ProxyCredentialControlResponse struct {
	Version           int
	OperationID       string
	Action            uint8
	OK                bool
	CredentialContext string
	ServerInvalidated bool
	Error             *ProxyError
}

func proxyHexIdentity(s string) bool {
	if len(s) != 32 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func proxyCredentialContext(s string) bool {
	if len(s) != 43 {
		return false
	}
	value, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(value) == 32 && base64.RawURLEncoding.EncodeToString(value) == s
}
func checkProxyCredentialMetadata(private, selection, origin string) error {
	if private != "" && !proxyCredentialContext(private) {
		return CBORFailure("proxy_credential_context")
	}
	if selection != "" && selection != "omit" && selection != "same-origin" && selection != "include" {
		return CBORFailure("proxy_credentials")
	}
	if !proxyASCII(origin) {
		return CBORFailure("proxy_request_origin")
	}
	return nil
}
func CheckProxyCredentialControlRequest(v ProxyCredentialControlRequest) error {
	if v.Version != proxyApplication.Version || !proxyHexIdentity(v.OperationID) || !proxyHexIdentity(v.SurfaceOwner) || v.Action < 1 || v.Action > 3 {
		return CBORFailure("proxy_credential_control")
	}
	if v.Action == 1 {
		if v.CredentialContext != "" || v.ContentOrigin == "" || !proxyASCII(v.ContentOrigin) {
			return CBORFailure("proxy_credential_control")
		}
	} else if v.ContentOrigin != "" || !proxyCredentialContext(v.CredentialContext) {
		return CBORFailure("proxy_credential_control")
	}
	return nil
}
func CheckProxyCredentialControlResponse(v ProxyCredentialControlResponse) error {
	if v.Version != proxyApplication.Version || !proxyHexIdentity(v.OperationID) || v.Action < 1 || v.Action > 3 {
		return CBORFailure("proxy_credential_control")
	}
	if !v.OK {
		if v.Error == nil || v.CredentialContext != "" || v.Action == 1 && v.ServerInvalidated {
			return CBORFailure("proxy_credential_control")
		}
		return nil
	}
	if v.Error != nil {
		return CBORFailure("proxy_credential_control")
	}
	if v.Action == 1 && (!proxyCredentialContext(v.CredentialContext) || v.ServerInvalidated) || v.Action == 2 && (!proxyCredentialContext(v.CredentialContext) || !v.ServerInvalidated) || v.Action == 3 && (v.CredentialContext != "" || !v.ServerInvalidated) {
		return CBORFailure("proxy_credential_control")
	}
	return nil
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
	case ProxyCredentialControlRequest, *ProxyCredentialControlRequest:
		return "ProxyCredentialControlRequest"
	case ProxyCredentialControlResponse, *ProxyCredentialControlResponse:
		return "ProxyCredentialControlResponse"
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
	for _, name := range []string{"request_id", "method", "path", "external_origin", "conn_id", "protocol", "credential_context", "credentials", "request_origin", "operation_id", "surface_owner", "content_origin"} {
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
	case *ProxyCredentialControlRequest:
		*v = ProxyCredentialControlRequest{Version: version, OperationID: getBytes("operation_id"), Action: uint8(getUint("action")), SurfaceOwner: getBytes("surface_owner"), CredentialContext: getBytes("credential_context"), ContentOrigin: getBytes("content_origin")}
		return CheckProxyCredentialControlRequest(*v)
	case *ProxyCredentialControlResponse:
		ok, _ := root.Named(schema, "ok").Bool()
		invalidated, _ := root.Named(schema, "server_invalidated").Bool()
		problem, err := getError()
		if err != nil {
			return err
		}
		*v = ProxyCredentialControlResponse{Version: version, OperationID: getBytes("operation_id"), Action: uint8(getUint("action")), OK: ok, CredentialContext: getBytes("credential_context"), ServerInvalidated: invalidated, Error: problem}
		if root.Named(schema, "server_invalidated").valid() && !invalidated {
			return CBORFailure("proxy_credential_control")
		}
		return CheckProxyCredentialControlResponse(*v)
	case *ProxyHTTPRequest:
		if err := checkProxyCredentialMetadata(getBytes("credential_context"), getBytes("credentials"), getBytes("request_origin")); err != nil {
			return err
		}
		if !ProxyASCIIToken(getBytes("method")) {
			return CBORFailure("proxy_method")
		}
		*v = ProxyHTTPRequest{version, getBytes("request_id"), getBytes("method"), getBytes("path"), h, getBytes("external_origin"), int64(getUint("timeout_ms")), getBytes("credential_context"), getBytes("credentials"), getBytes("request_origin")}
	case *ProxyWebSocketOpen:
		if err := checkProxyCredentialMetadata(getBytes("credential_context"), getBytes("credentials"), getBytes("request_origin")); err != nil {
			return err
		}
		*v = ProxyWebSocketOpen{version, getBytes("conn_id"), getBytes("path"), h, getBytes("credential_context"), getBytes("credentials"), getBytes("request_origin")}
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
	case ProxyCredentialControlRequest:
		if err := CheckProxyCredentialControlRequest(v); err != nil {
			return nil, err
		}
		add("operation_id", v.OperationID)
		add("surface_owner", v.SurfaceOwner)
		fields = append(fields, Field{Name: "action", Number: uint64(v.Action)})
		if v.CredentialContext != "" {
			add("credential_context", v.CredentialContext)
		}
		if v.ContentOrigin != "" {
			add("content_origin", v.ContentOrigin)
		}
		fieldName = ""
	case ProxyCredentialControlResponse:
		if err := CheckProxyCredentialControlResponse(v); err != nil {
			return nil, err
		}
		add("operation_id", v.OperationID)
		fields = append(fields, Field{Name: "action", Number: uint64(v.Action)}, Field{Name: "ok", Kind: Boolean})
		if v.OK {
			fields[len(fields)-1].Number = 1
		}
		if v.CredentialContext != "" {
			add("credential_context", v.CredentialContext)
		}
		if v.ServerInvalidated {
			fields = append(fields, Field{Name: "server_invalidated", Kind: Boolean, Number: 1})
		}
		problem = v.Error
		fieldName = ""
	case ProxyHTTPRequest:
		if err := checkProxyCredentialMetadata(v.CredentialContext, v.Credentials, v.RequestOrigin); err != nil {
			return nil, err
		}
		if v.Version != proxyApplication.Version || v.TimeoutMS < 0 || v.TimeoutMS > 300000 || !ProxyASCIIToken(v.Method) {
			return nil, CBORFailure("proxy_version")
		}
		add("request_id", v.RequestID)
		add("method", v.Method)
		add("path", v.Path)
		headers = v.Headers
		if v.CredentialContext != "" {
			add("credential_context", v.CredentialContext)
		}
		if v.Credentials != "" {
			add("credentials", v.Credentials)
		}
		if v.RequestOrigin != "" {
			add("request_origin", v.RequestOrigin)
		}
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
		if err := checkProxyCredentialMetadata(v.CredentialContext, v.Credentials, v.RequestOrigin); err != nil {
			return nil, err
		}
		if v.Version != proxyApplication.Version {
			return nil, CBORFailure("proxy_version")
		}
		add("conn_id", v.ConnID)
		add("path", v.Path)
		headers = v.Headers
		if v.CredentialContext != "" {
			add("credential_context", v.CredentialContext)
		}
		if v.Credentials != "" {
			add("credentials", v.Credentials)
		}
		if v.RequestOrigin != "" {
			add("request_origin", v.RequestOrigin)
		}
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
