package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"strconv"
	"sync"
	"unsafe"
)

// ServiceContractCodec keeps the exact canonical contract until Release. The
// caller supplies a finite node cap; this is byte validation, not installation
// in a trusted registry, caller permission, a store promise or dispatch rights.
type ServiceContractCodec struct {
	mu      sync.Mutex
	decoder *Decoder
	current *ServiceContract
}
type ServiceContract struct {
	codec    *ServiceContractCodec
	document *Document
	digest   [32]byte
}

func ServiceContractBackingBytes(nodeCap int) (uint64, error) {
	n, err := SchemaByteLimit("ServiceContract")
	if err != nil {
		return 0, err
	}
	if nodeCap <= 0 || nodeCap > n*2 {
		return 0, CBORFailure("configuration_capacity")
	}
	// Every text field in the closed ServiceContract graph is a <=128-byte
	// security identifier. Opaque definition bytes are not normalized text.
	cost, err := decoderBackingBytes(n, nodeCap, 128)
	return cost + uint64(unsafe.Sizeof(ServiceContractCodec{})) + uint64(unsafe.Sizeof(ServiceContract{})), err
}
func NewServiceContractCodec(nodeCap int) (*ServiceContractCodec, error) {
	if _, err := ServiceContractBackingBytes(nodeCap); err != nil {
		return nil, err
	}
	n, err := SchemaByteLimit("ServiceContract")
	if err != nil {
		return nil, err
	}
	d, err := newDecoder(n, nodeCap, 128)
	if err != nil {
		return nil, err
	}
	return &ServiceContractCodec{decoder: d}, nil
}
func (c *ServiceContractCodec) Decode(wire []byte) (*ServiceContract, error) {
	if c == nil || c.decoder == nil {
		return nil, CBORFailure("configuration_capacity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	doc, err := c.decoder.DecodeMap(wire, "ServiceContract", DecodeContext{})
	if err != nil {
		return nil, err
	}
	digest, err := fullMapDigest("service_contract_digest", "ServiceContract", doc.Bytes())
	if err != nil {
		doc.Release()
		return nil, err
	}
	result := &ServiceContract{codec: c, document: doc, digest: digest}
	c.current = result
	return result, nil
}
func (c *ServiceContract) Release() {
	if c == nil || c.codec == nil {
		return
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current == c {
		c.document.Release()
		c.codec.current = nil
	}
}
func (c *ServiceContract) Digest() ([32]byte, error) {
	if c == nil || c.codec == nil {
		return [32]byte{}, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return [32]byte{}, CBORFailure("document_released")
	}
	return c.digest, nil
}
func (*ServiceContract) String() string               { return "Flowersec.ServiceContract" }
func (*ServiceContract) GoString() string             { return "Flowersec.ServiceContract" }
func (*ServiceContract) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type applicationRequestRegistry struct {
	variants  map[string]map[string]uint64
	execution map[string]bool
	label     []byte
}

var runtimeApplicationRequests = sync.OnceValues(func() (*applicationRequestRegistry, error) {
	var wire struct {
		Policy struct {
			Execution []string                     `json:"execution_requests"`
			Variants  map[string]map[string]uint64 `json:"contract_variants"`
		}
	}
	if err := json.Unmarshal([]byte(ApplicationHeaderRegistryJSON), &wire); err != nil {
		return nil, err
	}
	r := &applicationRequestRegistry{variants: wire.Policy.Variants, execution: make(map[string]bool)}
	for _, name := range wire.Policy.Execution {
		r.execution[name] = true
	}
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
		Input           struct {
			Parts []struct {
				Name, Encoding string
				Schema         string `json:"schema_ref"`
				Projection     string
			}
		} `json:"input_schema"`
		Output int `json:"output_length"`
	}
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if domain.Name != "execution_request_digest" {
			continue
		}
		parts := domain.Input.Parts
		if r.label != nil || domain.Operation != "sha256" || domain.Output != 32 || len(parts) != 8 {
			return nil, CBORFailure("registry_unresolved")
		}
		for i, pair := range [...][2]string{{"contract", "lp-map"}, {"message_kind", "u8"}, {"operation_id", "lp-bytes"}, {"type_id", "u32"}, {"deadline_at_ms", "u64"}, {"admission_mode", "u8"}, {"response_limit_bytes", "u32"}, {"payload", "lp-bytes"}} {
			if parts[i].Name != pair[0] || parts[i].Encoding != pair[1] {
				return nil, CBORFailure("registry_unresolved")
			}
		}
		if parts[0].Schema != "ServiceContract" || parts[0].Projection != "full" {
			return nil, CBORFailure("registry_unresolved")
		}
		var err error
		r.label, err = hex.DecodeString(domain.Label)
		if err != nil || len(r.label) == 0 || r.label[len(r.label)-1] != 0 {
			return nil, CBORFailure("registry_unresolved")
		}
	}
	if r.label == nil || len(r.variants) == 0 || len(r.execution) == 0 {
		return nil, CBORFailure("registry_unresolved")
	}
	return r, nil
})

func (c *ServiceContract) checkRequestLocked(h ApplicationHeader) error {
	if c.codec.current != c {
		return CBORFailure("document_released")
	}
	if h.name == "" || h.IsResponse() {
		return CBORFailure("application_contract_variant")
	}
	r, err := runtimeApplicationRequests()
	if err != nil {
		return err
	}
	shape, ok := r.variants[h.name]
	if !ok {
		return CBORFailure("application_contract_variant")
	}
	root := c.document.Root()
	typeID, _ := root.Named("ServiceContract", "type_id").Uint()
	if h.fields.Type != uint32(typeID) || h.fields.ServiceContractDigest != c.digest {
		return CBORFailure("application_contract_binding")
	}
	for key, expected := range shape {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return CBORFailure("registry_unresolved")
		}
		actual, ok := root.Field(id).Uint()
		if !ok || actual != expected {
			return CBORFailure("application_contract_variant")
		}
	}
	requestMax, _ := root.Named("ServiceContract", "request_max_bytes").Uint()
	if uint64(h.fields.PayloadBytes) > requestMax {
		return CBORFailure("application_request_limit")
	}
	if h.HasResponseLimit() {
		minimum, _ := root.Named("ServiceContract", "min_response_limit_bytes").Uint()
		maximum, _ := root.Named("ServiceContract", "max_response_bytes").Uint()
		limit := uint64(h.fields.ResponseLimitBytes)
		if limit < minimum || limit > maximum {
			return CBORFailure("application_response_limit")
		}
	}
	return nil
}
func (c *ServiceContract) CheckRequest(h ApplicationHeader) error {
	if c == nil || c.codec == nil {
		return CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	return c.checkRequestLocked(h)
}

// ExecutionRequestVerifier hashes only the actual contiguous original payload.
// It retains no payload/contract aliases and never hashes a response as a new
// request. Aborted/partial input cannot pass Finish. This single-reader object
// proves the digest relation only; actual execution still needs its original
// full-input owner, trusted registry, authorization, admission and store gates.
type ExecutionRequestVerifier struct {
	hash        hash.Hash
	expected    [32]byte
	total, next uint32
	closed      bool
}

func ExecutionRequestVerifierBackingBytes(hashRuntimeBytes uint64) (uint64, error) {
	fixed := uint64(unsafe.Sizeof(ExecutionRequestVerifier{})) + 128
	if hashRuntimeBytes == 0 || hashRuntimeBytes > ^uint64(0)-fixed {
		return 0, CBORFailure("configuration_capacity")
	}
	// The qualified Go hash/runtime allowance includes the concrete hash
	// allocation and call overhead, independent of the retained payload owner.
	return fixed + hashRuntimeBytes, nil
}
func NewExecutionRequestVerifier(h ApplicationHeader, c *ServiceContract) (*ExecutionRequestVerifier, error) {
	return newExecutionRequestVerifier(h, c, false)
}

// NewExecutionRejectionVerifier validates a known exact contract digest even
// when the request violates that contract's shape, type or limits. This owner
// grants only the input integrity fact needed by a bounded service refusal;
// it never authorizes capture, application input delivery or execution.
func NewExecutionRejectionVerifier(h ApplicationHeader, c *ServiceContract) (*ExecutionRequestVerifier, error) {
	return newExecutionRequestVerifier(h, c, true)
}

func newExecutionRequestVerifier(h ApplicationHeader, c *ServiceContract, rejection bool) (*ExecutionRequestVerifier, error) {
	if c == nil || c.codec == nil {
		return nil, CBORFailure("document_released")
	}
	r, err := runtimeApplicationRequests()
	if err != nil {
		return nil, err
	}
	if !r.execution[h.name] || !h.HasExecutionIdentity() || !h.HasResponseLimit() || !h.HasDeadline() {
		return nil, CBORFailure("application_execution_request")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return nil, CBORFailure("document_released")
	}
	if h.fields.ServiceContractDigest != c.digest {
		return nil, CBORFailure("application_contract_binding")
	}
	if !rejection {
		if err := c.checkRequestLocked(h); err != nil {
			return nil, err
		}
	}
	v := &ExecutionRequestVerifier{hash: sha256.New(), expected: h.fields.RequestDigest, total: h.fields.PayloadBytes}
	_, _ = v.hash.Write(r.label)
	var scalar [8]byte
	writeU32 := func(n uint32) { binary.BigEndian.PutUint32(scalar[:4], n); _, _ = v.hash.Write(scalar[:4]) }
	contract := c.document.Bytes()
	writeU32(uint32(len(contract)))
	_, _ = v.hash.Write(contract)
	scalar[0] = h.fields.Kind
	_, _ = v.hash.Write(scalar[:1])
	writeU32(32)
	_, _ = v.hash.Write(h.fields.OperationID[:])
	writeU32(h.fields.Type)
	binary.BigEndian.PutUint64(scalar[:], h.fields.DeadlineAtMS)
	_, _ = v.hash.Write(scalar[:])
	scalar[0] = h.fields.AdmissionMode
	_, _ = v.hash.Write(scalar[:1])
	writeU32(h.fields.ResponseLimitBytes)
	writeU32(h.fields.PayloadBytes)
	return v, nil
}

// ComputeExecutionRequestDigest binds the exact canonical contract and all
// immutable execution fields to the complete prepared payload. The caller
// replaces only request_digest in its provisional header before publication.
// Prepared-operation ownership supplies the hash runtime and payload backing.
func ComputeExecutionRequestDigest(h ApplicationHeader, c *ServiceContract, payload []byte) ([32]byte, error) {
	if uint64(len(payload)) != uint64(h.fields.PayloadBytes) {
		return [32]byte{}, CBORFailure("application_payload_length")
	}
	v, err := NewExecutionRequestVerifier(h, c)
	if err != nil {
		return [32]byte{}, err
	}
	defer v.Close()
	if len(payload) != 0 {
		if err = v.WriteAt(0, payload); err != nil {
			return [32]byte{}, err
		}
	}
	var digest [32]byte
	v.hash.Sum(digest[:0])
	return digest, nil
}

func (v *ExecutionRequestVerifier) WriteAt(offset uint32, data []byte) error {
	if v == nil || v.closed || v.hash == nil {
		return CBORFailure("application_input_closed")
	}
	if offset != v.next || len(data) == 0 || uint64(len(data)) > uint64(v.total-v.next) {
		v.Close()
		return CBORFailure("application_payload_length")
	}
	_, _ = v.hash.Write(data)
	v.next += uint32(len(data))
	return nil
}
func (v *ExecutionRequestVerifier) Finish() error {
	if v == nil || v.closed || v.hash == nil {
		return CBORFailure("application_input_closed")
	}
	defer v.Close()
	if v.next != v.total {
		return CBORFailure("application_payload_length")
	}
	var digest [32]byte
	v.hash.Sum(digest[:0])
	if digest != v.expected {
		return CBORFailure("application_request_digest")
	}
	return nil
}
func (v *ExecutionRequestVerifier) Close() {
	if v == nil || v.closed {
		return
	}
	v.closed = true
	if v.hash != nil {
		v.hash.Reset()
		v.hash = nil
	}
	clear(v.expected[:])
}
