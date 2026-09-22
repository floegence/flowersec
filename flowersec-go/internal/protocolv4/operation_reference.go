package protocolv4

import (
	"encoding/binary"
	"sync"
	"unsafe"
)

// OperationReference is an immutable, bounded query locator. Its value has
// no reference to a local operation, Session, codec, provider, or credentials.
// Decoding it can never reconstruct an execution or publication capability.
type OperationReference struct {
	text                                    [5][128]byte
	length                                  [5]uint8
	authority, operation, request, contract [32]byte
	deadline                                uint64
	shape, mode, cancel                     uint8
	valid                                   bool
}

func (r OperationReference) Valid() bool          { return r.valid }
func (r OperationReference) TargetDomain() string { return string(r.text[0][:r.length[0]]) }
func (r OperationReference) Target() ManagementTarget {
	if !r.valid {
		return ManagementTarget{}
	}
	return ManagementTarget{Tenant: string(r.text[1][:r.length[1]]), Audience: string(r.text[2][:r.length[2]]), Namespace: string(r.text[3][:r.length[3]]), Subject: string(r.text[4][:r.length[4]]), Authority: r.authority, Operation: r.operation, RequestDigest: r.request, ContractDigest: r.contract}
}
func (r OperationReference) AdmissionNotAfterMS() uint64 {
	return binary.BigEndian.Uint64(r.operation[:8])
}
func (r OperationReference) DeadlineAtMS() uint64       { return r.deadline }
func (r OperationReference) CallShape() uint8           { return r.shape }
func (r OperationReference) ExecutionMode() uint8       { return r.mode }
func (r OperationReference) CancelMode() uint8          { return r.cancel }
func (OperationReference) String() string               { return "Flowersec.OperationReference" }
func (OperationReference) GoString() string             { return "Flowersec.OperationReference" }
func (OperationReference) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// The caller owns this admitted reusable local persistence codec. It has no
// file path, store, trust resolver or Start method; import resolves only the
// supplied exact local target domain, not a root embedded in saved bytes.
type OperationReferenceCodec struct {
	mu      sync.Mutex
	decoder *Decoder
	headers *ApplicationHeaderCodec
	target  [1024]byte
	wire    [2048]byte
}

func OperationReferenceCodecBackingBytes() (uint64, error) {
	n, err := decoderBackingBytes(2048, 64, 640)
	if err != nil {
		return 0, err
	}
	h, err := ApplicationHeaderBackingBytes()
	return h + n + uint64(unsafe.Sizeof(OperationReferenceCodec{})) + 2*uint64(unsafe.Sizeof(OperationReference{})) + 2*640, err
}
func NewOperationReferenceCodec() (*OperationReferenceCodec, error) {
	d, err := newDecoder(2048, 64, 640)
	if err != nil {
		return nil, err
	}
	h, err := NewApplicationHeaderCodec()
	if err != nil {
		return nil, err
	}
	return &OperationReferenceCodec{decoder: d, headers: h}, nil
}

func (c *OperationReferenceCodec) Capture(domain string, target ManagementTarget, header ApplicationHeader, policy ServiceContractPolicy) (OperationReference, error) {
	if !header.HasExecutionIdentity() || policy.Semantics != 1 {
		return OperationReference{}, CBORFailure("execution_reference_required")
	}
	h := header.Fields()
	if h.OperationID != target.Operation || h.RequestDigest != target.RequestDigest || h.ServiceContractDigest != target.ContractDigest || policy.Digest != target.ContractDigest || policy.Namespace != target.Namespace || h.Type != policy.Type {
		return OperationReference{}, CBORFailure("execution_reference_binding")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(c.wire[:])
	n, err := c.encode(c.wire[:], domain, target, h.DeadlineAtMS, policy.Shape, policy.ExecutionMode, policy.CancelMode)
	if err != nil {
		return OperationReference{}, err
	}
	return c.decode(c.wire[:n], domain)
}

// Import validates the canonical saved value and the trusted configured
// domain. Its fields remain untrusted selectors for a newly authorized query.
func (c *OperationReferenceCodec) Import(wire []byte, expectedDomain string) (OperationReference, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decode(wire, expectedDomain)
}

func (c *OperationReferenceCodec) decode(wire []byte, expectedDomain string) (out OperationReference, err error) {
	doc, err := c.decoder.DecodeMap(wire, "OperationReference", DecodeContext{})
	if err != nil {
		return out, err
	}
	defer doc.Release()
	r := doc.Root()
	domain, _ := r.Named("OperationReference", "target_domain").Text()
	if expectedDomain == "" || domain != expectedDomain {
		return out, CBORFailure("execution_reference_domain")
	}
	target := r.Named("OperationReference", "target")
	texts := [5]string{domain}
	for i, name := range [...]string{"tenant_id", "audience", "service_namespace", "caller_subject"} {
		texts[i+1], _ = target.Named("ExecutionManagementTarget", name).Text()
	}
	for i, text := range texts {
		out.length[i] = uint8(copy(out.text[i][:], text))
	}
	for _, field := range []struct {
		name   string
		target *[32]byte
	}{{"caller_authority", &out.authority}, {"operation_id", &out.operation}, {"request_digest", &out.request}, {"service_contract_digest", &out.contract}} {
		b, _ := target.Named("ExecutionManagementTarget", field.name).ByteString()
		copy(field.target[:], b)
		if *field.target == ([32]byte{}) {
			return OperationReference{}, CBORFailure("execution_reference_binding")
		}
	}
	out.deadline, _ = r.Named("OperationReference", "deadline_at_ms").Uint()
	for _, field := range []struct {
		name   string
		target *uint8
	}{{"call_shape", &out.shape}, {"execution_mode", &out.mode}, {"cancel_mode", &out.cancel}} {
		n, _ := r.Named("OperationReference", field.name).Uint()
		*field.target = uint8(n)
	}
	if out.AdmissionNotAfterMS() == 0 || out.AdmissionNotAfterMS() > out.deadline {
		return OperationReference{}, CBORFailure("execution_reference_cutoff")
	}
	out.valid = true
	return out, nil
}

func (c *OperationReferenceCodec) Export(dst []byte, ref OperationReference) (int, error) {
	if !ref.valid {
		return 0, CBORFailure("execution_reference_required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.encode(dst, ref.TargetDomain(), ref.Target(), ref.deadline, ref.shape, ref.mode, ref.cancel)
}
func (c *OperationReferenceCodec) encode(dst []byte, domain string, t ManagementTarget, deadline uint64, shape, mode, cancel uint8) (int, error) {
	defer clear(c.target[:])
	wire, err := EncodeMap(c.target[:], "ExecutionManagementTarget", []Field{{Name: "tenant_id", Kind: TextString, Text: t.Tenant}, {Name: "audience", Kind: TextString, Text: t.Audience}, {Name: "service_namespace", Kind: TextString, Text: t.Namespace}, {Name: "caller_subject", Kind: TextString, Text: t.Subject}, {Name: "caller_authority", Kind: ByteString, Bytes: t.Authority[:]}, {Name: "operation_id", Kind: ByteString, Bytes: t.Operation[:]}, {Name: "request_digest", Kind: ByteString, Bytes: t.RequestDigest[:]}, {Name: "service_contract_digest", Kind: ByteString, Bytes: t.ContractDigest[:]}})
	if err != nil {
		return 0, err
	}
	wire, err = EncodeMap(dst, "OperationReference", []Field{{Name: "format_version", Number: 1}, {Name: "target_domain", Kind: TextString, Text: domain}, {Name: "target", Kind: EncodedMap, Bytes: wire}, {Name: "call_shape", Number: uint64(shape)}, {Name: "execution_mode", Number: uint64(mode)}, {Name: "deadline_at_ms", Number: deadline}, {Name: "cancel_mode", Number: uint64(cancel)}})
	if err != nil {
		return 0, err
	}
	return len(wire), nil
}

// EncodeResultRead creates only the existing fixed bounded read request. The
// selector bytes are not credentials and this never creates an execution ID.
func (c *OperationReferenceCodec) EncodeResultRead(header, payload []byte, ref OperationReference, typeID uint32, contract [32]byte, deadline uint64) (ApplicationHeader, int, int, error) {
	if c == nil || !ref.Valid() || ref.CallShape() != 0 || typeID == 0 || contract == ([32]byte{}) || deadline == 0 {
		return ApplicationHeader{}, 0, 0, CBORFailure("execution_reference_binding")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t := ref.Target()
	body, err := EncodeMap(payload, "ExecutionManagementTarget", []Field{{Name: "tenant_id", Kind: TextString, Text: t.Tenant}, {Name: "audience", Kind: TextString, Text: t.Audience}, {Name: "service_namespace", Kind: TextString, Text: t.Namespace}, {Name: "caller_subject", Kind: TextString, Text: t.Subject}, {Name: "caller_authority", Kind: ByteString, Bytes: t.Authority[:]}, {Name: "operation_id", Kind: ByteString, Bytes: t.Operation[:]}, {Name: "request_digest", Kind: ByteString, Bytes: t.RequestDigest[:]}, {Name: "service_contract_digest", Kind: ByteString, Bytes: t.ContractDigest[:]}})
	if err != nil {
		return ApplicationHeader{}, 0, 0, err
	}
	n, h, err := c.headers.Encode(header, "read_result_request", ApplicationHeaderFields{Type: typeID, ServiceContractDigest: contract, DeadlineAtMS: deadline, PayloadBytes: uint32(len(body))})
	return h, n, len(body), err
}
