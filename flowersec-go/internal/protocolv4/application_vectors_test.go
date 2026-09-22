package protocolv4

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

type applicationVector struct {
	ID, Hex, Kind string
	Accept        bool
	ExpectedError string `json:"expected_error"`
}
type applicationFixtures struct {
	r       *applicationReference
	vectors []applicationVector
	seeds   map[string][]byte
}

func newApplicationFixtures(t testing.TB) *applicationFixtures {
	t.Helper()
	f := &applicationFixtures{r: newApplicationReference(t), seeds: map[string][]byte{}}
	raw, err := os.ReadFile("../../../testdata/transport_v4/application_headers.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Revision string `json:"schema_revision"`
		Vectors  []applicationVector
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	f.vectors = corpus.Vectors
	raw, err = os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var maps struct {
		Revision string `json:"schema_revision"`
		SHA      string `json:"schema_sha256"`
	}
	if err := json.Unmarshal(raw, &maps); err != nil {
		t.Fatal(err)
	}
	if corpus.Revision != maps.Revision || maps.SHA != SchemaSHA256 {
		t.Fatal("application corpus binding drift")
	}
	for _, v := range cborRefVectors(t) {
		f.seeds[v.ID] = domainHex(t, v.Hex)
	}
	return f
}
func (f *applicationFixtures) maximum(t testing.TB, kind string) *cborRefValue {
	t.Helper()
	for _, v := range f.vectors {
		if v.Accept && v.Kind == kind {
			header, err := f.r.header(domainHex(t, v.Hex))
			if err != nil {
				t.Fatal(err)
			}
			return header.value
		}
	}
	t.Fatalf("missing application kind %s", kind)
	return nil
}
func (f *applicationFixtures) read(t testing.TB, name string, input []byte) *cborRefValue {
	t.Helper()
	v, err := f.r.rawMap(name, input)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func (f *applicationFixtures) change(t testing.TB, name string, v *cborRefValue, key string, replacement *cborRefValue) *cborRefValue {
	t.Helper()
	id, _, err := f.r.namedField(name, key)
	if err != nil {
		t.Fatal(err)
	}
	out := &cborRefValue{major: 5}
	for _, pair := range v.pairs {
		if pair[0].n != id {
			out.pairs = append(out.pairs, pair)
		}
	}
	if replacement != nil {
		out.pairs = append(out.pairs, [2]*cborRefValue{{major: 0, n: id}, replacement})
	}
	sort.Slice(out.pairs, func(i, j int) bool { return out.pairs[i][0].n < out.pairs[j][0].n })
	return out
}
func appUint(n uint64) *cborRefValue    { return &cborRefValue{major: 0, n: n} }
func appBytes(raw []byte) *cborRefValue { return &cborRefValue{major: 2, data: raw} }
func appFailure(t testing.TB, err error, code string) {
	t.Helper()
	if _, ok := err.(cborRefError); !ok {
		t.Fatalf("expected reference rejection, got %v", err)
	}
	if code != "" && err.Error() != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
func appOK(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func (f *applicationFixtures) hash(t testing.TB, name string, args map[string]any) []byte {
	t.Helper()
	raw, err := f.r.hash(name, args)
	appOK(t, err)
	return raw
}
func (f *applicationFixtures) pair(t testing.TB, requestKind, responseKind string, length, limit uint64) (*cborRefValue, *cborRefValue) {
	t.Helper()
	request, response := f.maximum(t, requestKind), f.maximum(t, responseKind)
	if f.r.value("ApplicationHeader", request, "response_limit_bytes") != nil {
		request = f.change(t, "ApplicationHeader", request, "response_limit_bytes", appUint(limit))
	}
	return request, f.change(t, "ApplicationHeader", response, "payload_length", appUint(length))
}
func (f *applicationFixtures) execution(t testing.TB, kind string) (*cborRefValue, []byte, []byte) {
	t.Helper()
	suffix := map[string]string{"execution_unary_request": "unary_execution", "execution_stream_request": "stream_execution", "execution_notify": "notify_execution", "resume_request": "unary_execution"}[kind]
	contract, payload := f.seeds["service_"+suffix], []byte{1, 2, 3}
	definition := f.read(t, "ServiceContract", contract)
	header := f.maximum(t, kind)
	for key, value := range map[string]*cborRefValue{
		"type_id": f.r.value("ServiceContract", definition, "type_id"), "payload_length": appUint(uint64(len(payload))),
		"service_contract_digest": appBytes(f.hash(t, "service_contract_digest", map[string]any{"contract": contract})),
		"response_limit_bytes":    f.r.value("ServiceContract", definition, "max_response_bytes"),
	} {
		header = f.change(t, "ApplicationHeader", header, key, value)
	}
	digest, err := f.r.executionDigest(header.encode(nil), contract, payload)
	appOK(t, err)
	return f.change(t, "ApplicationHeader", header, "request_digest", appBytes(digest)), contract, payload
}

// v4.go_application.corpus
func TestCBORApplicationCorpus(t *testing.T) {
	f := newApplicationFixtures(t)
	kinds := map[string]bool{}
	rejected := 0
	if len(f.vectors) != 589 {
		t.Fatal("application corpus coverage changed")
	}
	for _, v := range f.vectors {
		t.Run(v.ID, func(t *testing.T) {
			raw := domainHex(t, v.Hex)
			header, err := f.r.header(raw)
			if !v.Accept {
				rejected++
				expected := ""
				if strings.HasPrefix(v.ExpectedError, "application_") {
					expected = v.ExpectedError
				}
				appFailure(t, err, expected)
				return
			}
			appOK(t, err)
			kinds[header.kind] = true
			if header.kind != v.Kind || !bytes.Equal(header.value.encode(nil), raw) || uint64(len(raw)) != f.r.application.Kinds[header.kind].MaxEncodedBytes {
				t.Fatal("exact header mismatch")
			}
		})
	}
	if len(kinds) != len(f.r.application.Kinds) || rejected != 558 {
		t.Fatal("incomplete exact-header coverage")
	}
	_, err := f.r.header(f.change(t, "ApplicationHeader", f.maximum(t, "execution_notify"), "response_limit_bytes", appUint(1)).encode(nil))
	appFailure(t, err, "application_constant")
}

// v4.go_application.response_binding
func TestCBORApplicationResponseBinding(t *testing.T) {
	f := newApplicationFixtures(t)
	for kind, variant := range f.r.application.Kinds {
		if variant.Request == "" {
			continue
		}
		t.Run(kind, func(t *testing.T) {
			request, response := f.pair(t, variant.Request, kind, 0, 0)
			_, err := f.r.response(request.encode(nil), response.encode(nil))
			appOK(t, err)
			for _, name := range []string{"operation_id", "type_id", "request_digest", "service_contract_digest", "control_serial"} {
				value := f.r.value("ApplicationHeader", response, name)
				if value == nil {
					continue
				}
				replacement := appBytes(bytes.Repeat([]byte{7}, 32))
				if value.major == 0 {
					replacement = appUint(value.n - 1)
				}
				_, err := f.r.response(request.encode(nil), f.change(t, "ApplicationHeader", response, name, replacement).encode(nil))
				appFailure(t, err, "application_response_binding")
			}
			for _, name := range []string{"deadline_at_ms", "admission_mode", "response_limit_bytes"} {
				for _, n := range []uint64{0, 1} {
					_, err := f.r.response(request.encode(nil), f.change(t, "ApplicationHeader", response, name, appUint(n)).encode(nil))
					appFailure(t, err, "application_fields")
				}
			}
			for other, v := range f.r.application.Kinds {
				if v.Request != "" || other == variant.Request {
					continue
				}
				_, err := f.r.response(f.maximum(t, other).encode(nil), response.encode(nil))
				appFailure(t, err, "application_response_kind")
			}
		})
	}
}

// v4.go_application.execution_digest
func TestCBORApplicationExecutionDigest(t *testing.T) {
	f := newApplicationFixtures(t)
	for _, kind := range f.r.application.Policy.ExecutionRequests {
		t.Run(kind, func(t *testing.T) {
			header, contract, payload := f.execution(t, kind)
			appOK(t, f.r.verifyExecution(header.encode(nil), contract, payload))
			for name, value := range map[string]*cborRefValue{"deadline_at_ms": appUint(17), "admission_mode": appUint(0), "operation_id": appBytes(make([]byte, 32))} {
				appFailure(t, f.r.verifyExecution(f.change(t, "ApplicationHeader", header, name, value).encode(nil), contract, payload), "application_request_digest")
			}
			appFailure(t, f.r.verifyExecution(header.encode(nil), contract, []byte{1, 2, 4}), "application_request_digest")
			appFailure(t, f.r.verifyExecution(header.encode(nil), contract, nil), "application_payload_length")
			_, err := f.r.executionDigest(f.change(t, "ApplicationHeader", header, "type_id", appUint(900)).encode(nil), contract, payload)
			appFailure(t, err, "application_contract_binding")
			changed := f.change(t, "ServiceContract", f.read(t, "ServiceContract", contract), "request_schema_revision", &cborRefValue{major: 3, data: []byte("changed")}).encode(nil)
			appFailure(t, f.r.verifyExecution(header.encode(nil), changed, payload), "application_contract_binding")
			header = f.change(t, "ApplicationHeader", header, "service_contract_digest", appBytes(f.hash(t, "service_contract_digest", map[string]any{"contract": changed})))
			appFailure(t, f.r.verifyExecution(header.encode(nil), changed, payload), "application_request_digest")
		})
	}
	header, contract, payload := f.execution(t, "execution_unary_request")
	_, err := f.r.executionDigest(f.change(t, "ApplicationHeader", header, "message_kind", appUint(f.r.application.Kinds["execution_stream_request"].Code)).encode(nil), contract, payload)
	appFailure(t, err, "application_contract_variant")
	for kind := range f.r.application.Kinds {
		if slices.Contains(f.r.application.Policy.ExecutionRequests, kind) {
			continue
		}
		_, err := f.r.executionDigest(f.maximum(t, kind).encode(nil), contract, payload)
		appFailure(t, err, "application_execution_request")
	}
	small := f.change(t, "ServiceContract", f.read(t, "ServiceContract", contract), "request_max_bytes", appUint(2)).encode(nil)
	_, err = f.r.executionDigest(f.change(t, "ApplicationHeader", header, "service_contract_digest", appBytes(f.hash(t, "service_contract_digest", map[string]any{"contract": small}))).encode(nil), small, payload)
	appFailure(t, err, "application_request_limit")
	limited := f.change(t, "ServiceContract", f.change(t, "ServiceContract", f.read(t, "ServiceContract", contract), "max_response_bytes", appUint(2)), "min_response_limit_bytes", appUint(1)).encode(nil)
	header = f.change(t, "ApplicationHeader", header, "service_contract_digest", appBytes(f.hash(t, "service_contract_digest", map[string]any{"contract": limited})))
	for _, n := range []uint64{0, 3} {
		_, err := f.r.executionDigest(f.change(t, "ApplicationHeader", header, "response_limit_bytes", appUint(n)).encode(nil), limited, payload)
		appFailure(t, err, "application_response_limit")
	}
	for _, length := range []int{0, 1048576} {
		header, contract, _ := f.execution(t, "execution_unary_request")
		payload := make([]byte, length)
		header = f.change(t, "ApplicationHeader", header, "payload_length", appUint(uint64(length)))
		digest, err := f.r.executionDigest(header.encode(nil), contract, payload)
		appOK(t, err)
		header = f.change(t, "ApplicationHeader", header, "request_digest", appBytes(digest))
		appOK(t, f.r.verifyExecution(header.encode(nil), contract, payload))
	}
}

// v4.go_application.sdk_stop
func TestCBORApplicationSDKStop(t *testing.T) {
	f := newApplicationFixtures(t)
	if reflect.TypeFor[applicationSDKResult]().NumField() != 1 {
		t.Fatal("SDK projection must contain only code")
	}
	for kind, variant := range f.r.application.Kinds {
		if !variant.SDKError {
			continue
		}
		for label, code := range f.r.application.SDKCodes {
			t.Run(kind+"/"+label, func(t *testing.T) {
				value, err := f.r.namedMap(f.r.application.SDKErrors.PayloadSchema, map[string]*cborRefValue{"code": appUint(code)})
				appOK(t, err)
				body := value.encode(nil)
				request, response := f.pair(t, variant.Request, kind, uint64(len(body)), 0)
				result, err := f.r.sdkError(request.encode(nil), response.encode(nil), body)
				stream := kind == "execution_stream_sdk_error" || kind == "transient_stream_sdk_error"
				if stream && (label == "request_message_aborted" || label == "response_output_stopped") {
					appFailure(t, err, "streaming_sdk_error_code")
					return
				}
				if !stream && label == "source_overflow" {
					appFailure(t, err, "application_sdk_error_code")
					return
				}
				appOK(t, err)
				if result.Code != label {
					t.Fatal(result)
				}
				for _, n := range []uint64{0, 1, 255, 256} {
					_, err := f.r.response(request.encode(nil), f.change(t, "ApplicationHeader", response, "payload_length", appUint(n)).encode(nil))
					appOK(t, err)
				}
				_, err = f.r.response(request.encode(nil), f.change(t, "ApplicationHeader", response, "payload_length", appUint(257)).encode(nil))
				appFailure(t, err, "application_sdk_error_limit")
				_, err = f.r.sdkError(request.encode(nil), response.encode(nil), make([]byte, 257))
				appFailure(t, err, "application_input_size")
				_, err = f.r.sdkError(request.encode(nil), response.encode(nil), body[:len(body)-1])
				appFailure(t, err, "application_payload_length")
				for _, text := range []string{"a10000", "a10019ffff", "a0", "a200010100", "a200010001", "a1180001", "a1000100", "a100"} {
					raw := domainHex(t, text)
					_, err := f.r.sdkError(request.encode(nil), f.change(t, "ApplicationHeader", response, "payload_length", appUint(uint64(len(raw)))).encode(nil), raw)
					appFailure(t, err, "")
				}
				if f.r.value("ApplicationHeader", request, "response_limit_bytes") != nil {
					for other, v := range f.r.application.Kinds {
						if v.Request != variant.Request || v.SDKError {
							continue
						}
						req, res := f.pair(t, variant.Request, other, 1, 0)
						_, err := f.r.response(req.encode(nil), res.encode(nil))
						appFailure(t, err, "application_response_limit")
					}
				}
			})
		}
	}
	request, response := f.pair(t, "transient_unary_request", "transient_unary_response", 0, 0)
	_, err := f.r.sdkError(request.encode(nil), response.encode(nil), nil)
	appFailure(t, err, "application_sdk_error_kind")
}

// v4.go_application.business_errors
func TestCBORApplicationBusinessErrors(t *testing.T) {
	f := newApplicationFixtures(t)
	schema := domainHex(t, "a10001")
	definition, err := f.r.namedMap("ErrorDefinition", map[string]*cborRefValue{"code": appUint(12345), "schema_revision": {major: 3, data: []byte("error-1")}, "max_payload_bytes": appUint(2), "schema_digest": appBytes(f.hash(t, "business_error_schema_digest", map[string]any{"error_schema": schema}))})
	appOK(t, err)
	appOK(t, f.r.matchErrorSchema(definition.encode(nil), schema))
	appFailure(t, f.r.matchErrorSchema(definition.encode(nil), domainHex(t, "a0")), "application_error_schema_mismatch")
	appFailure(t, f.r.matchErrorSchema(definition.encode(nil), make([]byte, 8193)), "application_input_size")
	for _, semantics := range []string{"execution", "transient"} {
		for _, shape := range []string{"unary", "stream"} {
			t.Run(semantics+"/"+shape, func(t *testing.T) {
				contract := f.change(t, "ServiceContract", f.read(t, "ServiceContract", f.seeds["service_"+shape+"_"+semantics]), "application_error_catalog", &cborRefValue{major: 4, items: []*cborRefValue{definition}}).encode(nil)
				appOK(t, f.r.matchErrorCatalog(contract, [][]byte{definition.encode(nil)}))
				appFailure(t, f.r.matchErrorCatalog(contract, nil), "application_error_catalog_mismatch")
				appFailure(t, f.r.matchErrorCatalog(contract, make([][]byte, 65)), "application_error_catalog_size")
				for name, value := range map[string]*cborRefValue{"code": appUint(12346), "schema_revision": {major: 3, data: []byte("error-2")}, "max_payload_bytes": appUint(3), "schema_digest": appBytes(make([]byte, 32))} {
					appFailure(t, f.r.matchErrorCatalog(contract, [][]byte{f.change(t, "ErrorDefinition", definition, name, value).encode(nil)}), "application_error_catalog_mismatch")
				}
				request, response := f.pair(t, semantics+"_"+shape+"_request", semantics+"_"+shape+"_application_error", 2, 4)
				for _, side := range []**cborRefValue{&request, &response} {
					*side = f.change(t, "ApplicationHeader", *side, "service_contract_digest", appBytes(f.hash(t, "service_contract_digest", map[string]any{"contract": contract})))
					*side = f.change(t, "ApplicationHeader", *side, "type_id", f.r.value("ServiceContract", f.read(t, "ServiceContract", contract), "type_id"))
				}
				classify := func(length int, code uint64) (applicationBusinessResult, error) {
					res := f.change(t, "ApplicationHeader", f.change(t, "ApplicationHeader", response, "payload_length", appUint(uint64(length))), "application_error_code", appUint(code))
					return f.r.businessError(request.encode(nil), res.encode(nil), contract, make([]byte, length))
				}
				for _, row := range []struct {
					length         int
					code           uint64
					classification string
				}{{2, 12345, "known_application_error"}, {3, 12345, "application_result_decode_failed"}, {3, 0xffffffff, "unknown_application_error"}} {
					result, err := classify(row.length, row.code)
					appOK(t, err)
					if result != (applicationBusinessResult{Classification: row.classification, Code: row.code}) {
						t.Fatal(result)
					}
				}
				valid := f.change(t, "ApplicationHeader", response, "application_error_code", appUint(12345))
				_, err := f.r.businessError(request.encode(nil), valid.encode(nil), contract, make([]byte, 1))
				appFailure(t, err, "application_payload_length")
				_, err = f.r.businessError(request.encode(nil), valid.encode(nil), contract, make([]byte, 3))
				appFailure(t, err, "application_input_size")
				_, err = classify(5, 12345)
				appFailure(t, err, "application_response_limit")
				request = f.change(t, "ApplicationHeader", request, "response_limit_bytes", appUint(0))
				_, err = classify(0, 12345)
				appOK(t, err)
				_, err = classify(1, 12345)
				appFailure(t, err, "application_response_limit")
			})
		}
	}
}

// v4.go_application.ownership
func TestCBORApplicationOwnership(t *testing.T) {
	f := newApplicationFixtures(t)
	header, contract, payload := f.execution(t, "execution_unary_request")
	raw := header.encode(nil)
	before := bytes.Clone(raw)
	parsed, err := f.r.header(raw)
	appOK(t, err)
	clear(raw)
	if !bytes.Equal(parsed.value.encode(nil), before) {
		t.Fatal("returned fields alias input")
	}
	raw = bytes.Clone(before)
	parsed, err = f.r.header(raw)
	appOK(t, err)
	clear(parsed.raw)
	if !bytes.Equal(raw, before) {
		t.Fatal("returned bytes alias input")
	}
	_, err = f.r.header(make([]byte, 513))
	appFailure(t, err, "application_input_size")
	_, err = f.r.executionDigest(before, make([]byte, 8193), payload)
	appFailure(t, err, "application_input_size")
	_, err = f.r.executionDigest(before, contract, make([]byte, 1048577))
	appFailure(t, err, "application_input_size")
}

// v4.go_application.properties
func TestCBORApplicationProperties(t *testing.T) {
	f := newApplicationFixtures(t)
	var positives []applicationVector
	for _, v := range f.vectors {
		if v.Accept {
			positives = append(positives, v)
		}
	}
	state := uint32(0x235ba919)
	next := func() uint32 { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state }
	for i := 0; i < 4096; i++ {
		raw := domainHex(t, positives[int(next())%len(positives)].Hex)
		raw[int(next())%len(raw)] ^= 1 << (next() % 8)
		before := bytes.Clone(raw)
		attempt := func() string {
			header, err := f.r.header(raw)
			if err != nil {
				appFailure(t, err, "")
				return fmt.Sprint(err)
			}
			if !bytes.Equal(header.value.encode(nil), before) {
				t.Fatal("accepted bytes changed")
			}
			clear(header.raw)
			return header.kind
		}
		if attempt() != attempt() || !bytes.Equal(raw, before) {
			t.Fatal("mutation determinism or ownership failed")
		}
	}
}
