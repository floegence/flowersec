package protocolv4

// Encode builds only a registered exact variant, validates it using the same
// production decoder and copies it to admitted caller storage. Destination is
// unchanged on refusal. Fields absent from the variant must have zero local
// values; their absence is determined by the registry, never by zero omission.
func (c *ApplicationHeaderCodec) Encode(dst []byte, kind string, values ApplicationHeaderFields) (int, ApplicationHeader, error) {
	if c == nil || c.registry == nil {
		return 0, ApplicationHeader{}, CBORFailure("configuration_capacity")
	}
	var variant *headerVariantIndex
	for i := range c.registry.kinds {
		if c.registry.kinds[i].name == kind && kind != "" {
			variant = &c.registry.kinds[i]
			break
		}
	}
	if variant == nil {
		return 0, ApplicationHeader{}, CBORFailure("application_kind")
	}
	if values.Kind != 0 && values.Kind != variant.definition.Code {
		return 0, ApplicationHeader{}, CBORFailure("application_kind")
	}
	values.Kind = variant.definition.Code
	all := [11]Field{
		{Name: "message_kind", Number: uint64(values.Kind)},
		{Name: "operation_id", Kind: ByteString, Bytes: values.OperationID[:]},
		{Name: "type_id", Number: uint64(values.Type)},
		{Name: "payload_length", Number: uint64(values.PayloadBytes)},
		{Name: "request_digest", Kind: ByteString, Bytes: values.RequestDigest[:]},
		{Name: "deadline_at_ms", Number: values.DeadlineAtMS},
		{Name: "service_contract_digest", Kind: ByteString, Bytes: values.ServiceContractDigest[:]},
		{Name: "admission_mode", Number: uint64(values.AdmissionMode)},
		{Name: "response_limit_bytes", Number: uint64(values.ResponseLimitBytes)},
		{Name: "control_serial", Number: values.ControlSerial},
		{Name: "application_error_code", Number: uint64(values.ApplicationErrorCode)},
	}
	var fields [11]Field
	var present uint16
	for i, id := range variant.definition.Fields {
		fields[i] = all[id]
		present |= 1 << id
	}
	for id, f := range all {
		if present&(1<<id) != 0 {
			continue
		}
		if f.Number != 0 {
			return 0, ApplicationHeader{}, CBORFailure("application_fields")
		}
		for _, b := range f.Bytes {
			if b != 0 {
				return 0, ApplicationHeader{}, CBORFailure("application_fields")
			}
		}
	}
	var scratch [512]byte
	wire, err := EncodeMap(scratch[:], "ApplicationHeader", fields[:len(variant.definition.Fields)])
	if err != nil {
		return 0, ApplicationHeader{}, err
	}
	h, err := c.Decode(wire)
	if err != nil {
		return 0, ApplicationHeader{}, err
	}
	if len(dst) < len(wire) {
		return 0, ApplicationHeader{}, CBORFailure("configuration_capacity")
	}
	copy(dst, wire)
	return len(wire), h, nil
}

// EncodeSDKResponse preserves only the exact original response fields. It
// does not assert the stop/refusal's channel eligibility or execution outcome.
func (c *ApplicationHeaderCodec) EncodeSDKResponse(dst []byte, request ApplicationHeader, payloadBytes uint32) (int, ApplicationHeader, error) {
	if c == nil || c.registry == nil || request.Kind() == "" || request.IsResponse() {
		return 0, ApplicationHeader{}, CBORFailure("application_response_kind")
	}
	var kind string
	for _, v := range c.registry.kinds {
		if v.responseTo == request.fields.Kind && v.definition.SDKError {
			if kind != "" {
				return 0, ApplicationHeader{}, CBORFailure("registry_unresolved")
			}
			kind = v.name
		}
	}
	if kind == "" {
		return 0, ApplicationHeader{}, CBORFailure("application_response_kind")
	}
	v := request.Fields()
	v.Kind = 0
	v.PayloadBytes = payloadBytes
	v.DeadlineAtMS = 0
	v.AdmissionMode = 0
	v.ResponseLimitBytes = 0
	v.ApplicationErrorCode = 0
	n, h, err := c.Encode(dst, kind, v)
	if err != nil {
		return 0, ApplicationHeader{}, err
	}
	if err := request.MatchResponse(h); err != nil {
		return 0, ApplicationHeader{}, err
	}
	return n, h, nil
}
