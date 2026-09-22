package protocolv4

import (
	"encoding/json"
	"strconv"
	"sync"
	"unsafe"
)

// The generated registry owns the exact variants and their response relations.
// This compiled lookup is shared immutable Environment backing; it is not a
// peer-selected service registry and grants no dispatch or execution authority.
type headerVariant struct {
	Code      uint8
	Fields    []uint64
	Constants map[string]uint64
	Request   string
	SDKError  bool `json:"sdk_error"`
}
type headerVariantIndex struct {
	name       string
	definition headerVariant
	responseTo uint8
}
type headerRegistry struct {
	kinds                    [256]headerVariantIndex
	bytes, nodes, errorBytes int
	streamErrors             [1]uint64
	refusals                 [10]struct {
		Name  string
		Value uint64
	}
}

var runtimeApplicationHeaders = sync.OnceValues(func() (*headerRegistry, error) {
	var wire struct {
		Kinds     map[string]headerVariant
		SDKErrors struct {
			PayloadSchema   string   `json:"payload_schema"`
			RefusalCodes    []string `json:"refusal_codes"`
			StreamOnlyCodes []string `json:"stream_only_codes"`
		} `json:"sdk_errors"`
	}
	if err := json.Unmarshal([]byte(ApplicationHeaderRegistryJSON), &wire); err != nil {
		return nil, err
	}
	r := &headerRegistry{}
	if len(wire.SDKErrors.StreamOnlyCodes) != len(r.streamErrors) {
		return nil, CBORFailure("registry_unresolved")
	}
	for index, name := range wire.SDKErrors.StreamOnlyCodes {
		value, err := EnumValue("ApplicationSDKError", "code", name)
		if err != nil {
			return nil, err
		}
		r.streamErrors[index] = value
	}
	if len(wire.SDKErrors.RefusalCodes) != len(r.refusals) {
		return nil, CBORFailure("registry_unresolved")
	}
	for i, name := range wire.SDKErrors.RefusalCodes {
		if name == "request_message_aborted" || name == "response_output_stopped" {
			return nil, CBORFailure("registry_unresolved")
		}
		value, err := EnumValue("ApplicationSDKError", "code", name)
		if err != nil {
			return nil, err
		}
		for _, previous := range r.refusals[:i] {
			if previous.Name == name || previous.Value == value {
				return nil, CBORFailure("registry_unresolved")
			}
		}
		r.refusals[i].Name = name
		r.refusals[i].Value = value
	}
	var err error
	r.bytes, err = SchemaByteLimit("ApplicationHeader")
	if err != nil {
		return nil, err
	}
	r.errorBytes, err = SchemaByteLimit(wire.SDKErrors.PayloadSchema)
	if err != nil {
		return nil, err
	}
	// Every header member is an integer key and a scalar value. New nested or
	// larger headers require an explicit geometry update before admission.
	if r.bytes != 512 || r.errorBytes != 256 || len(wire.Kinds) == 0 {
		return nil, CBORFailure("registry_unresolved")
	}
	for name, variant := range wire.Kinds {
		if variant.Code == 0 || r.kinds[variant.Code].name != "" || len(variant.Fields) == 0 || len(variant.Fields) > 11 {
			return nil, CBORFailure("registry_unresolved")
		}
		var seen uint16
		for _, id := range variant.Fields {
			if id > 10 || seen&(1<<id) != 0 {
				return nil, CBORFailure("registry_unresolved")
			}
			seen |= 1 << id
		}
		for key := range variant.Constants {
			id, err := strconv.ParseUint(key, 10, 8)
			if err != nil || id > 10 || seen&(1<<id) == 0 {
				return nil, CBORFailure("registry_unresolved")
			}
		}
		r.nodes = max(r.nodes, 1+2*len(variant.Fields))
		r.kinds[variant.Code] = headerVariantIndex{name: name, definition: variant}
	}
	for code := range r.kinds {
		v := &r.kinds[code]
		if v.definition.Request != "" {
			request, ok := wire.Kinds[v.definition.Request]
			if !ok || request.Request != "" {
				return nil, CBORFailure("registry_unresolved")
			}
			v.responseTo = request.Code
		}
	}
	return r, nil
})

// ApplicationHeader is a detached, exactly validated scalar projection. The
// private presence mask distinguishes absent fields from an explicit zero;
// response deadlines and limits never overwrite an original request owner.
// Its validity proves syntax only, not routing, current permission or digest.
type ApplicationHeader struct {
	fields     ApplicationHeaderFields
	name       string
	responseTo uint8
	present    uint16
	sdkError   bool
}
type ApplicationHeaderFields struct {
	Kind, AdmissionMode                                          uint8
	Type, PayloadBytes, ResponseLimitBytes, ApplicationErrorCode uint32
	DeadlineAtMS, ControlSerial                                  uint64
	OperationID, RequestDigest, ServiceContractDigest            [32]byte
}

func (h ApplicationHeader) Fields() ApplicationHeaderFields { return h.fields }
func (h ApplicationHeader) Kind() string                    { return h.name }
func (h ApplicationHeader) IsResponse() bool                { return h.responseTo != 0 }
func (h ApplicationHeader) IsSDKError() bool                { return h.sdkError }
func (h ApplicationHeader) HasExecutionIdentity() bool      { return h.present&(1<<1) != 0 }
func (h ApplicationHeader) HasResponseLimit() bool          { return h.present&(1<<8) != 0 }
func (h ApplicationHeader) HasDeadline() bool               { return h.present&(1<<5) != 0 }
func (h ApplicationHeader) HasControlSerial() bool          { return h.present&(1<<9) != 0 }
func (ApplicationHeader) String() string                    { return "Flowersec.ApplicationHeader" }
func (ApplicationHeader) GoString() string                  { return "Flowersec.ApplicationHeader" }
func (ApplicationHeader) MarshalJSON() ([]byte, error)      { return []byte("{}"), nil }

// OrdinaryRPC excludes NOTIFY, dedicated typed streaming/Resume and M control.
// Neither a valid header nor a self-reported kind can select another framing.
func (h ApplicationHeader) OrdinaryRPC() bool {
	switch h.name {
	case "execution_unary_request", "execution_unary_response", "execution_unary_application_error", "execution_unary_sdk_error",
		"transient_unary_request", "transient_unary_response", "transient_unary_application_error", "transient_unary_sdk_error",
		"query_contracts_request", "query_contracts_response", "query_contracts_sdk_error",
		"read_result_request", "read_result_response", "read_result_sdk_error":
		return true
	default:
		return false
	}
}

// MatchResponse compares only original request fields defined by the exact
// variant. Fixed read limits and serial/channel association belong to the
// original request owner. Only the registered small SDK error has a separate
// payload reserve; application errors obey the normal response limit.
func (h ApplicationHeader) MatchResponse(response ApplicationHeader) error {
	if h.name == "" || h.IsResponse() || response.responseTo != h.fields.Kind {
		return CBORFailure("application_response_kind")
	}
	a, b := h.fields, response.fields
	if a.Type != b.Type || a.ServiceContractDigest != b.ServiceContractDigest ||
		h.HasExecutionIdentity() != response.HasExecutionIdentity() || a.OperationID != b.OperationID || a.RequestDigest != b.RequestDigest ||
		h.HasControlSerial() != response.HasControlSerial() || a.ControlSerial != b.ControlSerial {
		return CBORFailure("application_response_binding")
	}
	if h.HasResponseLimit() && !response.sdkError && b.PayloadBytes > a.ResponseLimitBytes {
		return CBORFailure("application_response_limit")
	}
	return nil
}

type ApplicationHeaderCodec struct {
	decoder  *Decoder
	registry *headerRegistry
}

// Admission includes the output scalar projection as well as the exclusive
// decoder. Callers retaining multiple headers charge every independent copy.
func ApplicationHeaderBackingBytes() (uint64, error) {
	r, err := runtimeApplicationHeaders()
	if err != nil {
		return 0, err
	}
	n, err := decoderBackingBytes(r.bytes, r.nodes, 0)
	return n + uint64(unsafe.Sizeof(ApplicationHeaderCodec{})) + uint64(unsafe.Sizeof(ApplicationHeader{})), err
}
func NewApplicationHeaderCodec() (*ApplicationHeaderCodec, error) {
	r, err := runtimeApplicationHeaders()
	if err != nil {
		return nil, err
	}
	d, err := newDecoder(r.bytes, r.nodes, 0)
	if err != nil {
		return nil, err
	}
	return &ApplicationHeaderCodec{decoder: d, registry: r}, nil
}
func (c *ApplicationHeaderCodec) Decode(input []byte) (ApplicationHeader, error) {
	var h ApplicationHeader
	if c == nil || c.decoder == nil {
		return h, CBORFailure("configuration_capacity")
	}
	doc, err := c.decoder.DecodeMap(input, "ApplicationHeader", DecodeContext{})
	if err != nil {
		return h, err
	}
	defer doc.Release()
	root := doc.Root()
	kind, ok := root.Named("ApplicationHeader", "message_kind").Uint()
	if !ok || kind > 255 {
		return h, CBORFailure("application_kind")
	}
	v := c.registry.kinds[kind]
	if v.name == "" {
		return h, CBORFailure("application_kind")
	}
	if root.Len() != len(v.definition.Fields) {
		return h, CBORFailure("application_fields")
	}
	for _, id := range v.definition.Fields {
		if !root.Field(id).valid() {
			return h, CBORFailure("application_fields")
		}
		h.present |= 1 << id
	}
	for key, expected := range v.definition.Constants {
		id, _ := strconv.ParseUint(key, 10, 8)
		n, ok := root.Field(id).Uint()
		if !ok || n != expected {
			return ApplicationHeader{}, CBORFailure("application_constant")
		}
	}
	uintField := func(name string) uint64 { n, _ := root.Named("ApplicationHeader", name).Uint(); return n }
	h.fields = ApplicationHeaderFields{Kind: uint8(kind), Type: uint32(uintField("type_id")), PayloadBytes: uint32(uintField("payload_length")), ResponseLimitBytes: uint32(uintField("response_limit_bytes")), DeadlineAtMS: uintField("deadline_at_ms"), AdmissionMode: uint8(uintField("admission_mode")), ControlSerial: uintField("control_serial"), ApplicationErrorCode: uint32(uintField("application_error_code"))}
	for _, field := range []struct {
		name string
		dst  *[32]byte
	}{{"operation_id", &h.fields.OperationID}, {"request_digest", &h.fields.RequestDigest}, {"service_contract_digest", &h.fields.ServiceContractDigest}} {
		b, _ := root.Named("ApplicationHeader", field.name).ByteString()
		copy(field.dst[:], b)
	}
	if v.definition.SDKError && h.fields.PayloadBytes > uint32(c.registry.errorBytes) {
		return ApplicationHeader{}, CBORFailure("application_sdk_error_limit")
	}
	h.name, h.responseTo, h.sdkError = v.name, v.responseTo, v.definition.SDKError
	return h, nil
}

// ApplicationRefusalCode resolves only the closed ordinary service-error
// subset. Message-stop codes have different original input/output gates.
func ApplicationRefusalCode(name string) (uint64, error) {
	r, err := runtimeApplicationHeaders()
	if err != nil {
		return 0, err
	}
	for _, code := range r.refusals {
		if code.Name == name {
			return code.Value, nil
		}
	}
	return 0, CBORFailure("application_sdk_error_code")
}

// ApplicationStreamErrorCode includes the source terminal specific to the
// dedicated stream. Ordinary RPC refusals cannot select it.
func ApplicationStreamErrorCode(name string) (uint64, error) {
	code, err := EnumValue("ApplicationSDKError", "code", name)
	if err != nil {
		return 0, err
	}
	if err := ValidateApplicationSDKErrorCode(code, true); err != nil {
		return 0, err
	}
	return code, nil
}

// ValidateApplicationSDKErrorCode fixes the carrier of every closed code.
// Request-stop and source-overflow meanings must not cross those boundaries.
func ValidateApplicationSDKErrorCode(code uint64, streaming bool) error {
	r, err := runtimeApplicationHeaders()
	if err != nil {
		return err
	}
	for _, refusal := range r.refusals {
		if refusal.Value == code {
			return nil
		}
	}
	if streaming {
		for _, value := range r.streamErrors {
			if value == code {
				return nil
			}
		}
		return CBORFailure("streaming_sdk_error_code")
	}
	for _, name := range [...]string{"request_message_aborted", "response_output_stopped"} {
		value, err := EnumValue("ApplicationSDKError", "code", name)
		if err != nil {
			return err
		}
		if value == code {
			return nil
		}
	}
	return CBORFailure("application_sdk_error_code")
}
