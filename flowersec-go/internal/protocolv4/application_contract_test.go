package protocolv4

import (
	"bytes"
	"testing"
)

func applicationContractCodecs(t testing.TB) (*ApplicationHeaderCodec, *ServiceContractCodec) {
	t.Helper()
	h, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewServiceContractCodec(2048)
	if err != nil {
		t.Fatal(err)
	}
	return h, c
}

// v4.go_rpc_codecs.execution_digest
func TestExecutionRequestVerifierOriginalReference(t *testing.T) {
	f := newApplicationFixtures(t)
	hc, cc := applicationContractCodecs(t)
	for _, kind := range f.r.application.Policy.ExecutionRequests {
		t.Run(kind, func(t *testing.T) {
			header, contract, payload := f.execution(t, kind)
			h, err := hc.Decode(header.encode(nil))
			if err != nil {
				t.Fatal(err)
			}
			c, err := cc.Decode(contract)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Release()
			digest, err := c.Digest()
			if err != nil || digest != h.fields.ServiceContractDigest {
				t.Fatal("original contract digest", err)
			}
			if err := c.CheckRequest(h); err != nil {
				t.Fatal(err)
			}
			v, err := NewExecutionRequestVerifier(h, c)
			if err != nil {
				t.Fatal(err)
			}
			for i := range payload {
				if err := v.WriteAt(uint32(i), payload[i:i+1]); err != nil {
					t.Fatal(err)
				}
			}
			if err := v.Finish(); err != nil {
				t.Fatal(err)
			}
			if err := v.Finish(); err == nil {
				t.Fatal("verification reused")
			}
		})
	}
}

func TestExecutionRequestVerifierEmptyAndDetached(t *testing.T) {
	f := newApplicationFixtures(t)
	hc, cc := applicationContractCodecs(t)
	header, contract, _ := f.execution(t, "execution_unary_request")
	header = f.change(t, "ApplicationHeader", header, "payload_length", appUint(0))
	expected, err := f.r.executionDigest(header.encode(nil), contract, nil)
	if err != nil {
		t.Fatal(err)
	}
	header = f.change(t, "ApplicationHeader", header, "request_digest", appBytes(expected))
	h, err := hc.Decode(header.encode(nil))
	if err != nil {
		t.Fatal(err)
	}
	c, err := cc.Decode(contract)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewExecutionRequestVerifier(h, c)
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	clear(contract)
	if _, err := c.Digest(); err == nil {
		t.Fatal("released contract usable")
	}
	if _, err := NewExecutionRequestVerifier(h, c); err == nil {
		t.Fatal("released contract recaptured")
	}
	if err := v.Finish(); err != nil {
		t.Fatal("original finite hash lost detached snapshot", err)
	}
}

func TestExecutionRequestVerifierIncompleteOrAltered(t *testing.T) {
	f := newApplicationFixtures(t)
	hc, cc := applicationContractCodecs(t)
	header, contract, payload := f.execution(t, "execution_unary_request")
	h, err := hc.Decode(header.encode(nil))
	if err != nil {
		t.Fatal(err)
	}
	c, err := cc.Decode(contract)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	for _, mode := range []string{"truncated", "wrong_bytes", "wrong_offset", "duplicate", "empty_data", "overrun", "aborted"} {
		t.Run(mode, func(t *testing.T) {
			v, err := NewExecutionRequestVerifier(h, c)
			if err != nil {
				t.Fatal(err)
			}
			var writeErr error
			switch mode {
			case "truncated":
				writeErr = v.WriteAt(0, payload[:1])
			case "wrong_bytes":
				wrong := bytes.Clone(payload)
				wrong[0] ^= 1
				writeErr = v.WriteAt(0, wrong)
			case "wrong_offset":
				writeErr = v.WriteAt(1, payload)
			case "duplicate":
				if err := v.WriteAt(0, payload[:1]); err != nil {
					t.Fatal(err)
				}
				writeErr = v.WriteAt(0, payload[:1])
			case "empty_data":
				writeErr = v.WriteAt(0, nil)
			case "overrun":
				writeErr = v.WriteAt(0, append(bytes.Clone(payload), 0))
			case "aborted":
				if err := v.WriteAt(0, payload[:1]); err != nil {
					t.Fatal(err)
				}
				v.Close()
			}
			if mode != "truncated" && mode != "wrong_bytes" && mode != "aborted" && writeErr == nil {
				t.Fatal("invalid input did not seal")
			}
			if err := v.Finish(); err == nil {
				t.Fatal("incomplete/altered request verified")
			}
			if err := v.WriteAt(0, payload); err == nil {
				t.Fatal("failed verifier reused")
			}
		})
	}
}

func TestApplicationContractBindingsBeforeHash(t *testing.T) {
	f := newApplicationFixtures(t)
	hc, cc := applicationContractCodecs(t)
	header, contract, _ := f.execution(t, "execution_unary_request")
	definition := f.read(t, "ServiceContract", contract)
	for key, value := range map[string]uint64{"request_max_bytes": 8, "min_response_limit_bytes": 16, "max_response_bytes": 16} {
		definition = f.change(t, "ServiceContract", definition, key, appUint(value))
	}
	contract = definition.encode(nil)
	header = f.change(t, "ApplicationHeader", header, "service_contract_digest", appBytes(f.hash(t, "service_contract_digest", map[string]any{"contract": contract})))
	header = f.change(t, "ApplicationHeader", header, "response_limit_bytes", appUint(16))
	c, err := cc.Decode(contract)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	for _, mode := range []string{"contract", "type", "limit", "payload", "response", "transient"} {
		t.Run(mode, func(t *testing.T) {
			candidate := header
			switch mode {
			case "contract":
				candidate = f.change(t, "ApplicationHeader", candidate, "service_contract_digest", appBytes(make([]byte, 32)))
			case "type":
				candidate = f.change(t, "ApplicationHeader", candidate, "type_id", appUint(0xffffffff))
			case "limit":
				candidate = f.change(t, "ApplicationHeader", candidate, "response_limit_bytes", appUint(17))
			case "payload":
				candidate = f.change(t, "ApplicationHeader", candidate, "payload_length", appUint(9))
			case "response":
				candidate = f.maximum(t, "execution_unary_response")
			case "transient":
				candidate = f.maximum(t, "transient_unary_request")
			}
			h, err := hc.Decode(candidate.encode(nil))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewExecutionRequestVerifier(h, c); err == nil {
				t.Fatal("unbound input admitted", mode)
			}
		})
	}
	if _, err := cc.Decode(contract); err == nil {
		t.Fatal("contract slot reused before release")
	}
}

func TestApplicationContractCorpusAndOwner(t *testing.T) {
	hc, cc := applicationContractCodecs(t)
	f := newApplicationFixtures(t)
	for _, name := range []string{"service_unary_execution", "service_stream_execution", "service_notify_execution", "service_unary_transient", "service_stream_transient", "service_notify_observation"} {
		c, err := cc.Decode(f.seeds[name])
		if err != nil {
			t.Fatal(name, err)
		}
		var kind string
		switch name {
		case "service_unary_execution":
			kind = "execution_unary_request"
		case "service_stream_execution":
			kind = "execution_stream_request"
		case "service_notify_execution":
			kind = "execution_notify"
		case "service_unary_transient":
			kind = "transient_unary_request"
		case "service_stream_transient":
			kind = "transient_stream_request"
		case "service_notify_observation":
			kind = "observation_notify"
		}
		value := f.read(t, "ServiceContract", f.seeds[name])
		header := f.maximum(t, kind)
		digest, _ := c.Digest()
		for key, replacement := range map[string]*cborRefValue{"type_id": f.r.value("ServiceContract", value, "type_id"), "service_contract_digest": appBytes(digest[:]), "payload_length": appUint(0), "response_limit_bytes": f.r.value("ServiceContract", value, "max_response_bytes")} {
			if key == "response_limit_bytes" && kind == "observation_notify" {
				continue
			}
			header = f.change(t, "ApplicationHeader", header, key, replacement)
		}
		h, err := hc.Decode(header.encode(nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CheckRequest(h); err != nil {
			t.Fatal(name, err)
		}
		if kind == "observation_notify" {
			if h.HasResponseLimit() || h.HasExecutionIdentity() || h.OrdinaryRPC() {
				t.Fatal("observation acquired response/execution/RPC fields")
			}
			if _, err := NewExecutionRequestVerifier(h, c); err != CBORFailure("application_execution_request") {
				t.Fatal("observation entered execution digest", err)
			}
		}
		c.Release()
		if err := c.CheckRequest(h); err == nil {
			t.Fatal("released contract authorized request")
		}
	}
}

func TestExecutionRequestVerifierFragmentedMaximumInput(t *testing.T) {
	f := newApplicationFixtures(t)
	hc, cc := applicationContractCodecs(t)
	header, contract, _ := f.execution(t, "execution_unary_request")
	payload := bytes.Repeat([]byte{0x79}, 1048576)
	header = f.change(t, "ApplicationHeader", header, "payload_length", appUint(uint64(len(payload))))
	digest, err := f.r.executionDigest(header.encode(nil), contract, payload)
	if err != nil {
		t.Fatal(err)
	}
	header = f.change(t, "ApplicationHeader", header, "request_digest", appBytes(digest))
	c, err := cc.Decode(contract)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	parser, err := NewRPCFragmentParser()
	if err != nil {
		t.Fatal(err)
	}
	defer parser.Close()
	var verifier *ExecutionRequestVerifier
	var buffer [16384]byte
	consume := func(fragment RPCFragment) {
		n, err := EncodeRPCFragment(buffer[:], fragment)
		if err != nil {
			t.Fatal(err)
		}
		for at := 0; at < n; {
			used, part, err := parser.Next(buffer[at:min(n, at+257)])
			if err != nil || used == 0 {
				t.Fatal("fragment progress", err)
			}
			at += used
			if part.Fragment.Serial == 0 {
				continue
			}
			if part.Fragment.Kind == RPCBegin {
				h, err := hc.Decode(part.Fragment.Header)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err = NewExecutionRequestVerifier(h, c)
				if err != nil {
					t.Fatal(err)
				}
			} else if err := verifier.WriteAt(part.Fragment.Offset+part.ChunkOffset, part.Fragment.Payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	consume(RPCFragment{Kind: RPCBegin, Serial: 1, Header: header.encode(nil)})
	for at := 0; at < len(payload); {
		end := min(len(payload), at+16367)
		consume(RPCFragment{Kind: RPCData, Serial: 1, Offset: uint32(at), Payload: payload[at:end]})
		at = end
	}
	if err := parser.End(); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionRequestVerifierOptionsRemainOriginal(t *testing.T) {
	f := newApplicationFixtures(t)
	hc, cc := applicationContractCodecs(t)
	header, contract, payload := f.execution(t, "execution_unary_request")
	c, err := cc.Decode(contract)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	for name, value := range map[string]*cborRefValue{"deadline_at_ms": appUint(17), "admission_mode": appUint(0), "operation_id": appBytes(make([]byte, 32)), "response_limit_bytes": appUint(0)} {
		h, err := hc.Decode(f.change(t, "ApplicationHeader", header, name, value).encode(nil))
		if err != nil {
			t.Fatal(err)
		}
		v, err := NewExecutionRequestVerifier(h, c)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.WriteAt(0, payload); err != nil {
			t.Fatal(err)
		}
		if err := v.Finish(); err != CBORFailure("application_request_digest") {
			t.Fatal("changed immutable option", name, err)
		}
	}
}

func TestServiceContractChecksOriginalResponseErrorCatalog(t *testing.T) {
	f := newApplicationFixtures(t)
	body := f.read(t, "ServiceContract", f.seeds["service_unary_transient"])
	definition := &cborRefValue{major: 5, pairs: [][2]*cborRefValue{
		{appUint(0), appUint(17)},
		{appUint(1), {major: 3, data: []byte("v1")}},
		{appUint(2), appUint(3)},
		{appUint(3), appBytes(bytes.Repeat([]byte{1}, 32))},
	}}
	body = f.change(t, "ServiceContract", body, "application_error_catalog", &cborRefValue{major: 4, items: []*cborRefValue{definition}})
	_, codec := applicationContractCodecs(t)
	contract, err := codec.Decode(body.encode(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	for _, test := range []struct {
		code, size uint32
		failure    string
	}{
		{0, 0, ""}, {0, 1048576, ""}, {0, 1048577, "application_response_limit"},
		{17, 0, ""}, {17, 3, ""}, {17, 4, "application_error_limit"}, {18, 0, "application_error_code"},
	} {
		err := contract.CheckResponsePayload(test.code, test.size)
		if test.failure == "" {
			if err != nil {
				t.Fatal(test, err)
			}
		} else if err != CBORFailure(test.failure) {
			t.Fatal(test, err)
		}
	}
	contract.Release()
	if err := contract.CheckResponsePayload(0, 0); err != CBORFailure("document_released") {
		t.Fatal(err)
	}
}
