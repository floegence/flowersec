package protocolv4

// Independent test-only application byte relations. Authentication, actual
// channel/serial ownership, admission, codec execution and publication remain external.
import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"testing"
)

type applicationVariant struct {
	Code            uint64
	Fields          []uint64
	Constants       map[string]uint64
	Request         string
	SDKError        bool   `json:"sdk_error"`
	BusinessError   bool   `json:"application_error"`
	MaxEncodedBytes uint64 `json:"max_encoded_bytes"`
}
type applicationRegistry struct {
	Kinds  map[string]applicationVariant
	Policy struct {
		ExecutionRequests []string                     `json:"execution_requests"`
		ContractVariants  map[string]map[string]uint64 `json:"contract_variants"`
	}
	SDKErrors struct {
		PayloadSchema string `json:"payload_schema"`
	} `json:"sdk_errors"`
	SDKCodes map[string]uint64 `json:"sdk_error_codes"`
}
type applicationHeader struct {
	kind  string
	value *cborRefValue
	raw   []byte
}
type applicationReference struct {
	*domainReference
	application applicationRegistry
	names       map[string]map[string]uint64
}

func newApplicationReference(t testing.TB) *applicationReference {
	t.Helper()
	r := &applicationReference{domainReference: newDomainReference(t), names: map[string]map[string]uint64{}}
	if err := json.Unmarshal([]byte(ApplicationHeaderRegistryJSON), &r.application); err != nil {
		t.Fatal(err)
	}
	for name, descriptor := range r.registry.Maps {
		r.names[name] = map[string]uint64{}
		for id, field := range descriptor.Fields {
			n, err := strconv.ParseUint(id, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			r.names[name][field.Name] = n
		}
	}
	return r
}

// Callers use generated field names only after a complete map passes wireMap.
// Optional header fields are explicitly nil-checked at their use sites.
func (r *applicationReference) value(name string, v *cborRefValue, field string) *cborRefValue {
	id, ok := r.names[name][field]
	if !ok {
		panic("unresolved generated field")
	}
	return cborLookup(v, id)
}
func (r *applicationReference) bound(name string) uint64 {
	bound := r.registry.Maps[name].MaxEncodedBytes
	if bound == nil {
		panic("unresolved generated bound")
	}
	return *bound
}
func applicationCapture(input []byte, bound uint64) ([]byte, error) {
	if uint64(len(input)) > bound {
		return nil, cborRefError("application_input_size")
	}
	return bytes.Clone(input), nil
}
func (r *applicationReference) rawMap(name string, input []byte) (*cborRefValue, error) {
	raw, err := applicationCapture(input, r.bound(name))
	if err != nil {
		return nil, err
	}
	return r.wireMap(raw, name, cborShapeContext{}, r.bound(name))
}
func (r *applicationReference) hash(name string, args map[string]any) ([]byte, error) {
	result, err := r.evaluate(name, args, cborShapeContext{}, r.bound("ServiceContract"))
	if err != nil {
		return nil, err
	}
	if result.Output == nil {
		return nil, cborRefError("registry_unresolved")
	}
	return result.Output, nil
}

func (r *applicationReference) header(input []byte) (*applicationHeader, error) {
	raw, err := applicationCapture(input, r.bound("ApplicationHeader"))
	if err != nil {
		return nil, err
	}
	v, err := r.wireMap(raw, "ApplicationHeader", cborShapeContext{}, r.bound("ApplicationHeader"))
	if err != nil {
		return nil, err
	}
	code := r.value("ApplicationHeader", v, "message_kind").n
	var kind string
	var variant applicationVariant
	for name, candidate := range r.application.Kinds {
		if candidate.Code == code {
			kind, variant = name, candidate
			break
		}
	}
	if kind == "" {
		return nil, cborRefError("application_kind")
	}
	if len(v.pairs) != len(variant.Fields) {
		return nil, cborRefError("application_fields")
	}
	for _, id := range variant.Fields {
		if cborLookup(v, id) == nil {
			return nil, cborRefError("application_fields")
		}
	}
	for key, expected := range variant.Constants {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, cborRefError("registry_unresolved")
		}
		actual := cborLookup(v, id)
		if actual == nil || actual.major != 0 || actual.n != expected {
			return nil, cborRefError("application_constant")
		}
	}
	if variant.SDKError && r.value("ApplicationHeader", v, "payload_length").n > r.bound(r.application.SDKErrors.PayloadSchema) {
		return nil, cborRefError("application_sdk_error_limit")
	}
	return &applicationHeader{kind: kind, value: v, raw: raw}, nil
}

func (r *applicationReference) response(original, input []byte) (*applicationHeader, error) {
	request, err := r.header(original)
	if err != nil {
		return nil, err
	}
	result, err := r.header(input)
	if err != nil {
		return nil, err
	}
	variant := r.application.Kinds[result.kind]
	if variant.Request != request.kind {
		return nil, cborRefError("application_response_kind")
	}
	for _, name := range []string{"operation_id", "type_id", "request_digest", "service_contract_digest", "control_serial"} {
		if !cborValuesEqual(r.value("ApplicationHeader", request.value, name), r.value("ApplicationHeader", result.value, name)) {
			return nil, cborRefError("application_response_binding")
		}
	}
	limit := r.value("ApplicationHeader", request.value, "response_limit_bytes")
	if limit != nil && !variant.SDKError && r.value("ApplicationHeader", result.value, "payload_length").n > limit.n {
		return nil, cborRefError("application_response_limit")
	}
	return result, nil
}

func (r *applicationReference) contract(header *applicationHeader, requestKind string, input []byte) ([]byte, *cborRefValue, error) {
	raw, err := applicationCapture(input, r.bound("ServiceContract"))
	if err != nil {
		return nil, nil, err
	}
	value, err := r.rawMap("ServiceContract", raw)
	if err != nil {
		return nil, nil, err
	}
	digest, err := r.hash("service_contract_digest", map[string]any{"contract": raw})
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(digest, r.value("ApplicationHeader", header.value, "service_contract_digest").data) || !cborValuesEqual(r.value("ApplicationHeader", header.value, "type_id"), r.value("ServiceContract", value, "type_id")) {
		return nil, nil, cborRefError("application_contract_binding")
	}
	shape, ok := r.application.Policy.ContractVariants[requestKind]
	if !ok {
		return nil, nil, cborRefError("application_contract_variant")
	}
	for key, expected := range shape {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, nil, cborRefError("registry_unresolved")
		}
		actual := cborLookup(value, id)
		if actual == nil || actual.major != 0 || actual.n != expected {
			return nil, nil, cborRefError("application_contract_variant")
		}
	}
	return raw, value, nil
}

func (r *applicationReference) executionDigest(input, contractInput, payloadInput []byte) ([]byte, error) {
	header, err := r.header(input)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(r.application.Policy.ExecutionRequests, header.kind) {
		return nil, cborRefError("application_execution_request")
	}
	contract, definition, err := r.contract(header, header.kind, contractInput)
	if err != nil {
		return nil, err
	}
	_, field, err := r.namedField("ApplicationHeader", "payload_length")
	if err != nil {
		return nil, err
	}
	if field.Max == nil {
		return nil, cborRefError("registry_unresolved")
	}
	payload, err := applicationCapture(payloadInput, uint64(*field.Max))
	if err != nil {
		return nil, err
	}
	if uint64(len(payload)) != r.value("ApplicationHeader", header.value, "payload_length").n {
		return nil, cborRefError("application_payload_length")
	}
	if uint64(len(payload)) > r.value("ServiceContract", definition, "request_max_bytes").n {
		return nil, cborRefError("application_request_limit")
	}
	limit := r.value("ApplicationHeader", header.value, "response_limit_bytes").n
	if limit < r.value("ServiceContract", definition, "min_response_limit_bytes").n || limit > r.value("ServiceContract", definition, "max_response_bytes").n {
		return nil, cborRefError("application_response_limit")
	}
	args := map[string]any{"contract": contract, "payload": payload}
	for _, name := range []string{"message_kind", "operation_id", "type_id", "deadline_at_ms", "admission_mode", "response_limit_bytes"} {
		value := r.value("ApplicationHeader", header.value, name)
		if value.major == 2 {
			args[name] = value.data
		} else {
			args[name] = value.n
		}
	}
	return r.hash("execution_request_digest", args)
}
func (r *applicationReference) verifyExecution(input, contract, payload []byte) error {
	header, err := r.header(input)
	if err != nil {
		return err
	}
	expected, err := r.executionDigest(header.raw, contract, payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, r.value("ApplicationHeader", header.value, "request_digest").data) {
		return cborRefError("application_request_digest")
	}
	return nil
}

func (r *applicationReference) matchErrorSchema(definition, registered []byte) error {
	value, err := r.rawMap("ErrorDefinition", definition)
	if err != nil {
		return err
	}
	domain, ok := r.domains["business_error_schema_digest"]
	if !ok || len(domain.Input.Parts) != 1 || domain.Input.Parts[0].MaxLength == nil {
		return cborRefError("registry_unresolved")
	}
	raw, err := applicationCapture(registered, uint64(*domain.Input.Parts[0].MaxLength))
	if err != nil {
		return err
	}
	digest, err := r.hash(domain.Name, map[string]any{"error_schema": raw})
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, r.value("ErrorDefinition", value, "schema_digest").data) {
		return cborRefError("application_error_schema_mismatch")
	}
	return nil
}
func (r *applicationReference) matchErrorCatalog(input []byte, definitions [][]byte) error {
	contract, err := r.rawMap("ServiceContract", input)
	if err != nil {
		return err
	}
	_, field, err := r.namedField("ServiceContract", "application_error_catalog")
	if err != nil {
		return err
	}
	if field.MaxItems == nil {
		return cborRefError("registry_unresolved")
	}
	if uint64(len(definitions)) > uint64(*field.MaxItems) {
		return cborRefError("application_error_catalog_size")
	}
	catalog := r.value("ServiceContract", contract, "application_error_catalog")
	if len(catalog.items) != len(definitions) {
		return cborRefError("application_error_catalog_mismatch")
	}
	for i, raw := range definitions {
		local, err := r.rawMap("ErrorDefinition", raw)
		if err != nil {
			return err
		}
		if !cborValuesEqual(catalog.items[i], local) {
			return cborRefError("application_error_catalog_mismatch")
		}
	}
	return nil
}

type applicationBusinessResult struct {
	Classification string
	Code           uint64
}

func (r *applicationReference) businessError(original, input, contractInput, payloadInput []byte) (applicationBusinessResult, error) {
	result := applicationBusinessResult{}
	header, err := r.response(original, input)
	if err != nil {
		return result, err
	}
	variant := r.application.Kinds[header.kind]
	if !variant.BusinessError {
		return result, cborRefError("application_error_kind")
	}
	_, contract, err := r.contract(header, variant.Request, contractInput)
	if err != nil {
		return result, err
	}
	payload, err := applicationCapture(payloadInput, r.value("ApplicationHeader", header.value, "payload_length").n)
	if err != nil {
		return result, err
	}
	if uint64(len(payload)) != r.value("ApplicationHeader", header.value, "payload_length").n {
		return result, cborRefError("application_payload_length")
	}
	result.Code = r.value("ApplicationHeader", header.value, "application_error_code").n
	result.Classification = "unknown_application_error"
	for _, entry := range r.value("ServiceContract", contract, "application_error_catalog").items {
		if r.value("ErrorDefinition", entry, "code").n != result.Code {
			continue
		}
		result.Classification = "known_application_error"
		if uint64(len(payload)) > r.value("ErrorDefinition", entry, "max_payload_bytes").n {
			result.Classification = "application_result_decode_failed"
		}
		break
	}
	// No application decoder, payload retention, execution or retry fact.
	return result, nil
}

type applicationSDKResult struct{ Code string }

func (r *applicationReference) sdkError(original, input, payloadInput []byte) (applicationSDKResult, error) {
	result := applicationSDKResult{}
	header, err := r.response(original, input)
	if err != nil {
		return result, err
	}
	if !r.application.Kinds[header.kind].SDKError {
		return result, cborRefError("application_sdk_error_kind")
	}
	name := r.application.SDKErrors.PayloadSchema
	payload, err := applicationCapture(payloadInput, r.bound(name))
	if err != nil {
		return result, err
	}
	if uint64(len(payload)) != r.value("ApplicationHeader", header.value, "payload_length").n {
		return result, cborRefError("application_payload_length")
	}
	value, err := r.rawMap(name, payload)
	if err != nil {
		return result, err
	}
	for code, n := range r.application.SDKCodes {
		if n == r.value(name, value, "code").n {
			stream := header.kind == "execution_stream_sdk_error" || header.kind == "transient_stream_sdk_error"
			if stream && (code == "request_message_aborted" || code == "response_output_stopped") {
				return result, cborRefError("streaming_sdk_error_code")
			}
			if !stream && code == "source_overflow" {
				return result, cborRefError("application_sdk_error_code")
			}
			result.Code = code
			return result, nil
		}
	}
	return result, cborRefError("application_sdk_error_code")
}
