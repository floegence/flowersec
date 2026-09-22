package protocolv4

import (
	"sync"
	"unsafe"
)

// ManagementTarget is a bounded wire projection, never an authorization or an
// execution-store selector. The receiving Session supplies current authority.
type ManagementTarget struct {
	Tenant, Audience, Namespace, Subject                string
	Authority, Operation, RequestDigest, ContractDigest [32]byte
}

type ManagementObservation struct {
	Found                                   bool
	State                                   uint8
	CancelRequested, Dispatched, WorkActive bool
	HistoryNotBeforeGCMS, ResultNotAfterMS  uint64
	ResultAvailable, ResultDeleted          bool
	ResultBytes, ApplicationErrorCode       uint32
	ResultDigest                            [32]byte
	Reason                                  string
}

// ManagementResult carries only small status metadata. Result payload reads
// use ordinary RPC and their independent original result ownership.
type ManagementResult struct {
	Status      string
	Observation ManagementObservation
	CancelKind  string
}

// ManagementCodec uses the four-SDK canonical schema with bounded reusable
// workspace. Construction requires its caller to admit BackingBytes first.
type ManagementCodec struct {
	mu      sync.Mutex
	decoder *Decoder
	scratch [256]byte
}

func ManagementCodecBackingBytes() (uint64, error) {
	n, err := decoderBackingBytes(1024, 64, 512)
	return n + uint64(unsafe.Sizeof(ManagementCodec{})) + 512, err
}
func NewManagementCodec() (*ManagementCodec, error) {
	d, err := newDecoder(1024, 64, 512)
	if err != nil {
		return nil, err
	}
	return &ManagementCodec{decoder: d}, nil
}

func (c *ManagementCodec) DecodeTarget(wire []byte) (ManagementTarget, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decodeTarget(wire)
}
func (c *ManagementCodec) decodeTarget(wire []byte) (ManagementTarget, error) {
	doc, err := c.decoder.DecodeMap(wire, "ExecutionManagementTarget", DecodeContext{})
	if err != nil {
		return ManagementTarget{}, err
	}
	defer doc.Release()
	r := doc.Root()
	var t ManagementTarget
	for _, v := range []struct {
		name string
		dst  *string
	}{{"tenant_id", &t.Tenant}, {"audience", &t.Audience}, {"service_namespace", &t.Namespace}, {"caller_subject", &t.Subject}} {
		*v.dst, _ = r.Named("ExecutionManagementTarget", v.name).Text()
	}
	for _, v := range []struct {
		name string
		dst  *[32]byte
	}{{"caller_authority", &t.Authority}, {"operation_id", &t.Operation}, {"request_digest", &t.RequestDigest}, {"service_contract_digest", &t.ContractDigest}} {
		b, _ := r.Named("ExecutionManagementTarget", v.name).ByteString()
		copy(v.dst[:], b)
	}
	return t, nil
}
func (c *ManagementCodec) EncodeTarget(dst []byte, t ManagementTarget) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wire, err := EncodeMap(dst, "ExecutionManagementTarget", []Field{
		{Name: "tenant_id", Kind: TextString, Text: t.Tenant}, {Name: "audience", Kind: TextString, Text: t.Audience}, {Name: "service_namespace", Kind: TextString, Text: t.Namespace}, {Name: "caller_subject", Kind: TextString, Text: t.Subject},
		{Name: "caller_authority", Kind: ByteString, Bytes: t.Authority[:]}, {Name: "operation_id", Kind: ByteString, Bytes: t.Operation[:]}, {Name: "request_digest", Kind: ByteString, Bytes: t.RequestDigest[:]}, {Name: "service_contract_digest", Kind: ByteString, Bytes: t.ContractDigest[:]},
	})
	if err == nil {
		_, err = c.decodeTarget(wire)
	}
	if err != nil {
		clear(wire)
		return 0, err
	}
	return len(wire), nil
}

func managementLabel(schema, field string, number uint64, labels []string) (string, error) {
	for _, label := range labels {
		n, err := EnumValue(schema, field, label)
		if err != nil {
			return "", err
		}
		if n == number {
			return label, nil
		}
	}
	return "", CBORFailure("enum_value")
}

var managementStatuses = [...]string{"ok", "unavailable", "unauthorized", "operation_conflict", "unsupported", "deadline_exceeded", "result_expired", "not_found", "history_unknown"}
var managementReasons = [...]string{"none", "cancelled", "dispatch_unavailable", "work_outcome_unknown", "deadline_exceeded", "not_registered", "history_unknown"}
var managementCancels = [...]string{"requested", "terminal", "not_registered", "history_unknown"}

func managementResponseSchema(cancel bool) string {
	if cancel {
		return "RequestCancelResponse"
	}
	return "QueryOperationResponse"
}

func (c *ManagementCodec) DecodeResult(wire []byte, cancel bool) (ManagementResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decodeResult(wire, cancel)
}
func (c *ManagementCodec) decodeResult(wire []byte, cancel bool) (ManagementResult, error) {
	schema := managementResponseSchema(cancel)
	doc, err := c.decoder.DecodeMap(wire, schema, DecodeContext{})
	if err != nil {
		return ManagementResult{}, err
	}
	defer doc.Release()
	r := doc.Root()
	var out ManagementResult
	n, _ := r.Named(schema, "status").Uint()
	out.Status, err = managementLabel(schema, "status", n, managementStatuses[:])
	if err != nil {
		return out, err
	}
	if !managementStatusHasObservation(out.Status) {
		return out, nil
	}
	if cancel {
		n, _ = r.Named(schema, "cancel_result").Uint()
		out.CancelKind, err = managementLabel(schema, "cancel_result", n, managementCancels[:])
		if err != nil {
			return out, err
		}
	}
	v := r.Named(schema, "observation")
	o := &out.Observation
	o.Found, _ = v.Named("ExecutionManagementObservation", "found").Bool()
	n, _ = v.Named("ExecutionManagementObservation", "reason").Uint()
	o.Reason, err = managementLabel("ExecutionManagementObservation", "reason", n, managementReasons[:])
	if err != nil {
		return out, err
	}
	if o.Reason == "none" {
		o.Reason = ""
	}
	if o.Found {
		n, _ = v.Named("ExecutionManagementObservation", "state").Uint()
		o.State = uint8(n)
		for _, f := range []struct {
			name string
			dst  *bool
		}{{"cancel_requested", &o.CancelRequested}, {"dispatched", &o.Dispatched}, {"work_active", &o.WorkActive}, {"result_available", &o.ResultAvailable}, {"result_deleted", &o.ResultDeleted}} {
			*f.dst, _ = v.Named("ExecutionManagementObservation", f.name).Bool()
		}
		o.HistoryNotBeforeGCMS, _ = v.Named("ExecutionManagementObservation", "history_not_before_gc_ms").Uint()
		o.ResultNotAfterMS, _ = v.Named("ExecutionManagementObservation", "result_not_after_ms").Uint()
		n, _ = v.Named("ExecutionManagementObservation", "result_bytes").Uint()
		o.ResultBytes = uint32(n)
		n, _ = v.Named("ExecutionManagementObservation", "application_error_code").Uint()
		o.ApplicationErrorCode = uint32(n)
		b, _ := v.Named("ExecutionManagementObservation", "result_digest").ByteString()
		copy(o.ResultDigest[:], b)
	}
	return out, nil
}
func managementBool(name string, v bool) Field {
	f := Field{Name: name, Kind: Boolean}
	if v {
		f.Number = 1
	}
	return f
}

func managementStatusHasObservation(status string) bool {
	return status == "ok" || status == "result_expired" || status == "not_found" || status == "history_unknown"
}

func (c *ManagementCodec) EncodeResult(dst []byte, result ManagementResult, cancel bool) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(c.scratch[:])
	schema := managementResponseSchema(cancel)
	status, err := EnumValue(schema, "status", result.Status)
	if err != nil {
		return 0, err
	}
	fields := [3]Field{{Name: "status", Number: status}}
	count := 1
	if managementStatusHasObservation(result.Status) {
		o := result.Observation
		reason := o.Reason
		if reason == "" {
			reason = "none"
		}
		reasonCode, err := EnumValue("ExecutionManagementObservation", "reason", reason)
		if err != nil {
			return 0, err
		}
		observed := [13]Field{managementBool("found", o.Found), {Name: "reason", Number: reasonCode}}
		length := 2
		if o.Found {
			rest := []Field{{Name: "state", Number: uint64(o.State)}, managementBool("cancel_requested", o.CancelRequested), managementBool("dispatched", o.Dispatched), managementBool("work_active", o.WorkActive), {Name: "history_not_before_gc_ms", Number: o.HistoryNotBeforeGCMS}, {Name: "result_not_after_ms", Number: o.ResultNotAfterMS}, managementBool("result_available", o.ResultAvailable), managementBool("result_deleted", o.ResultDeleted), {Name: "result_bytes", Number: uint64(o.ResultBytes)}, {Name: "application_error_code", Number: uint64(o.ApplicationErrorCode)}, {Name: "result_digest", Kind: ByteString, Bytes: o.ResultDigest[:]}}
			length += copy(observed[2:], rest)
		}
		body, err := EncodeMap(c.scratch[:], "ExecutionManagementObservation", observed[:length])
		if err != nil {
			return 0, err
		}
		fields[count] = Field{Name: "observation", Kind: EncodedMap, Bytes: body}
		count++
		if cancel {
			n, err := EnumValue(schema, "cancel_result", result.CancelKind)
			if err != nil {
				return 0, err
			}
			fields[count] = Field{Name: "cancel_result", Number: n}
			count++
		}
	}
	wire, err := EncodeMap(dst, schema, fields[:count])
	if err == nil {
		var decoded ManagementResult
		decoded, err = c.decodeResult(wire, cancel)
		if err == nil && decoded != result {
			err = CBORFailure("management_result_projection")
		}
	}
	if err != nil {
		clear(wire)
		return 0, err
	}
	return len(wire), nil
}
