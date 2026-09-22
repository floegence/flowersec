package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
)

// MethodShapeDigest compares the immutable wire-visible method definition.
// It is a local registration check, never a wire digest or compatibility proof
// for numeric policy, application codecs, handlers or persistence promises.
func (c *ServiceContract) MethodShapeDigest() ([32]byte, error) {
	if c == nil || c.codec == nil {
		return [32]byte{}, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return [32]byte{}, CBORFailure("document_released")
	}
	h := sha256.New()
	var size [8]byte
	for _, name := range [...]string{"service_namespace", "type_id", "call_shape", "unary_semantics", "server_streaming_semantics", "notify_semantics", "request_schema_revision", "response_schema_revision", "restart_flush", "restart_flush_deadline_ms", "application_error_catalog", "checkpoint_format"} {
		encoded := c.document.Root().Named("ServiceContract", name).Encoded()
		binary.BigEndian.PutUint64(size[:], uint64(len(encoded)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(encoded)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

// ServiceContractPolicy is a detached projection of the exact original
// canonical contract. It is not an advertisement, Offer, handler registration
// or permission to dispatch. Optional execution fields remain zero locally;
// the registered variant determines whether they exist on the wire.
type ServiceContractPolicy struct {
	Digest                                                                                       [32]byte
	Namespace                                                                                    string
	Type                                                                                         uint32
	Shape, Semantics, ExecutionMode, ResponseLimitMode                                           uint8
	CancelMode                                                                                   uint8
	CheckpointFormat                                                                             string
	Checkpoint, RetainedContent                                                                  bool
	Content                                                                                      StreamContentPolicy
	RequestMaxBytes, MinResponseBytes, MaxResponseBytes                                          uint32
	MaxItemCount                                                                                 uint32
	MaxStreamPayloadBytes, StreamDurationMS                                                      uint64
	MessageLifetimeMS, TransientRunMS                                                            uint64
	HistoryRetentionMS, ResultRetentionMS, AdmissionWindowMS, ExecutionHorizonMS, ExecutionRunMS uint64
}

func (c *ServiceContract) Policy() (ServiceContractPolicy, error) {
	if c == nil || c.codec == nil {
		return ServiceContractPolicy{}, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return ServiceContractPolicy{}, CBORFailure("document_released")
	}
	root := c.document.Root()
	get := func(name string) uint64 { n, _ := root.Named("ServiceContract", name).Uint(); return n }
	ns, _ := root.Named("ServiceContract", "service_namespace").Text()
	p := ServiceContractPolicy{Digest: c.digest, Namespace: ns, Type: uint32(get("type_id")), Shape: uint8(get("call_shape")), ExecutionMode: uint8(get("execution_mode")), ResponseLimitMode: uint8(get("response_limit_mode")), RequestMaxBytes: uint32(get("request_max_bytes")), MinResponseBytes: uint32(get("min_response_limit_bytes")), MaxResponseBytes: uint32(get("max_response_bytes")), MessageLifetimeMS: get("max_message_lifetime_ms"), TransientRunMS: get("max_transient_run_ms"), HistoryRetentionMS: get("history_retention_ms"), ResultRetentionMS: get("result_retention_ms"), AdmissionWindowMS: get("max_operation_admission_window_ms"), ExecutionHorizonMS: get("max_execution_horizon_ms"), ExecutionRunMS: get("max_execution_run_ms")}
	p.CancelMode = uint8(get("cancel_mode"))
	p.Checkpoint = root.Named("ServiceContract", "checkpoint_format").valid()
	p.CheckpointFormat, _ = root.Named("ServiceContract", "checkpoint_format").Text()
	if p.Shape == 1 {
		p.MaxItemCount = uint32(get("max_item_count"))
		p.MaxStreamPayloadBytes = get("max_stream_payload_bytes")
		p.StreamDurationMS = get("max_stream_duration_ms")
		content := root.Named("ServiceContract", "stream_content_policy")
		mode, _ := content.Named("StreamContentPolicy", "mode").Uint()
		p.RetainedContent = mode == 1
		if p.RetainedContent {
			origin, _ := content.Named("StreamContentPolicy", "retention_origin").Uint()
			p.Content.RetentionOrigin = uint8(origin)
			p.Content.RetentionMS, _ = content.Named("StreamContentPolicy", "retention_ms").Uint()
			p.Content.MaxItems, _ = content.Named("StreamContentPolicy", "max_retained_items").Uint()
			p.Content.MaxBytes, _ = content.Named("StreamContentPolicy", "max_retained_bytes").Uint()
			revision, _ := content.Named("StreamContentPolicy", "definition_schema_revision").Text()
			definition, _ := content.Named("StreamContentPolicy", "definition_bytes").ByteString()
			p.Content.Definition = StreamContentDefinitionDigest(revision, definition)
		}
	}
	switch p.Shape {
	case 0:
		p.Semantics = uint8(get("unary_semantics"))
	case 1:
		p.Semantics = uint8(get("server_streaming_semantics"))
	case 2:
		p.Semantics = uint8(get("notify_semantics"))
	default:
		return ServiceContractPolicy{}, CBORFailure("application_contract_variant")
	}
	return p, nil
}

// CopyCanonical copies the complete immutable contract into already admitted
// SDK output storage. No caller receives a mutable alias to the registry body.
func (c *ServiceContract) CopyCanonical(dst []byte) (int, error) {
	if c == nil || c.codec == nil {
		return 0, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return 0, CBORFailure("document_released")
	}
	wire := c.document.Bytes()
	if len(dst) < len(wire) {
		return 0, CBORFailure("configuration_capacity")
	}
	return copy(dst, wire), nil
}

// CanonicalSize reports only the retained original byte count. It does not
// parse again or expose mutable backing to a fixed SDK encoder.
func (c *ServiceContract) CanonicalSize() (int, error) {
	if c == nil || c.codec == nil {
		return 0, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return 0, CBORFailure("document_released")
	}
	return len(c.document.Bytes()), nil
}

// CopyCanonicalRange supports bounded fixed-codec steps. The original query
// owner must retain the body across calls; release can never substitute a new
// document behind an old contract reference. No mutable source alias escapes.
func (c *ServiceContract) CopyCanonicalRange(dst []byte, offset int) (int, error) {
	if c == nil || c.codec == nil {
		return 0, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return 0, CBORFailure("document_released")
	}
	wire := c.document.Bytes()
	if offset < 0 || offset > len(wire) {
		return 0, CBORFailure("encoder_offset")
	}
	return copy(dst, wire[offset:]), nil
}

// CheckResponsePayload validates service output against the original contract.
// The request's chosen response limit is enforced independently by its output
// owner. Unknown application codes may be received as opaque errors, but a
// local registered producer cannot invent codes outside its declared catalog.
func (c *ServiceContract) CheckResponsePayload(errorCode, payloadBytes uint32) error {
	if c == nil || c.codec == nil {
		return CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return CBORFailure("document_released")
	}
	root := c.document.Root()
	maximum, ok := root.Named("ServiceContract", "max_response_bytes").Uint()
	if !ok || uint64(payloadBytes) > maximum {
		return CBORFailure("application_response_limit")
	}
	if errorCode == 0 {
		return nil
	}
	catalog := root.Named("ServiceContract", "application_error_catalog")
	for i := 0; i < catalog.Len(); i++ {
		definition := catalog.Index(i)
		code, _ := definition.Named("ErrorDefinition", "code").Uint()
		if code != uint64(errorCode) {
			continue
		}
		limit, ok := definition.Named("ErrorDefinition", "max_payload_bytes").Uint()
		if !ok || uint64(payloadBytes) > limit {
			return CBORFailure("application_error_limit")
		}
		return nil
	}
	return CBORFailure("application_error_code")
}
