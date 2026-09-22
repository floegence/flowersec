package protocolv4

import (
	"bytes"
	"reflect"
	"sync"
	"testing"
)

// v4.go_rpc_codecs.headers
func TestApplicationHeaderCodecSharedCorpus(t *testing.T) {
	f := newApplicationFixtures(t)
	codec, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.vectors {
		t.Run(v.ID, func(t *testing.T) {
			h, err := codec.Decode(domainHex(t, v.Hex))
			if v.Accept {
				if err != nil || h.Kind() != v.Kind {
					t.Fatal(h.Kind(), err)
				}
				ref, err := f.r.header(domainHex(t, v.Hex))
				if err != nil {
					t.Fatal(err)
				}
				if h.fields.PayloadBytes != uint32(f.r.value("ApplicationHeader", ref.value, "payload_length").n) {
					t.Fatal("payload projection")
				}
			} else if err == nil {
				t.Fatal("malformed variant accepted")
			}
		})
	}
}

func TestApplicationHeaderOriginalResponseBinding(t *testing.T) {
	f := newApplicationFixtures(t)
	codec, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	decode := func(v *cborRefValue) ApplicationHeader {
		h, err := codec.Decode(v.encode(nil))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	for _, pair := range [][2]string{{"execution_unary_request", "execution_unary_response"}, {"transient_unary_request", "transient_unary_response"}, {"execution_unary_request", "execution_unary_application_error"}, {"transient_unary_request", "transient_unary_application_error"}} {
		t.Run(pair[1], func(t *testing.T) {
			request, response := f.pair(t, pair[0], pair[1], 0, 0)
			original, result := decode(request), decode(response)
			if err := original.MatchResponse(result); err != nil {
				t.Fatal(err)
			}
			if !original.HasResponseLimit() || result.HasResponseLimit() || result.HasDeadline() {
				t.Fatal("field presence erased explicit zero/absence")
			}
			tooLarge := decode(f.change(t, "ApplicationHeader", response, "payload_length", appUint(1)))
			if err := original.MatchResponse(tooLarge); err != CBORFailure("application_response_limit") {
				t.Fatal("zero success limit", err)
			}
			for _, name := range []string{"type_id", "service_contract_digest", "operation_id", "request_digest"} {
				if !original.HasExecutionIdentity() && (name == "operation_id" || name == "request_digest") {
					continue
				}
				v := appBytes(make([]byte, 32))
				if name == "type_id" {
					v = appUint(1)
				}
				wrong := decode(f.change(t, "ApplicationHeader", response, name, v))
				if err := original.MatchResponse(wrong); err != CBORFailure("application_response_binding") {
					t.Fatal(name, err)
				}
			}
		})
	}
	request, response := f.pair(t, "execution_unary_request", "execution_unary_sdk_error", 256, 0)
	original, result := decode(request), decode(response)
	if err := original.MatchResponse(result); err != nil || !result.IsSDKError() {
		t.Fatal(err)
	}
	tooLarge := f.change(t, "ApplicationHeader", response, "payload_length", appUint(257))
	if _, err := codec.Decode(tooLarge.encode(nil)); err == nil {
		t.Fatal("oversized small SDK error")
	}
	if err := original.MatchResponse(ApplicationHeader{}); err == nil {
		t.Fatal("zero header accepted")
	}
	if err := result.MatchResponse(original); err == nil {
		t.Fatal("response used as request")
	}
}

func TestApplicationHeaderDetachedAndFraming(t *testing.T) {
	f := newApplicationFixtures(t)
	codec, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	ordinary := map[string]bool{}
	for _, name := range []string{"execution_unary", "transient_unary", "query_contracts", "read_result"} {
		ordinary[name+"_request"], ordinary[name+"_response"], ordinary[name+"_sdk_error"] = true, true, true
	}
	ordinary["execution_unary_application_error"], ordinary["transient_unary_application_error"] = true, true
	for _, v := range f.vectors {
		if !v.Accept {
			continue
		}
		wire := domainHex(t, v.Hex)
		h, err := codec.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		frozen := h
		clear(wire)
		if _, err := codec.Decode([]byte{0xff}); err == nil {
			t.Fatal("invalid next input accepted")
		}
		if !reflect.DeepEqual(h, frozen) {
			t.Fatal("reused decoder mutated retained header")
		}
		if h.OrdinaryRPC() != ordinary[v.Kind] {
			t.Fatal("wrong framing", v.Kind)
		}
		if raw, _ := h.MarshalJSON(); !bytes.Equal(raw, []byte("{}")) {
			t.Fatal("header debug projection")
		}
	}
}

func TestApplicationHeaderCodecConcurrentOwnership(t *testing.T) {
	f := newApplicationFixtures(t)
	codec, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var wire []byte
	for _, v := range f.vectors {
		if v.Accept {
			wire = domainHex(t, v.Hex)
			break
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				h, err := codec.Decode(wire)
				if err == nil && h.Kind() == "" {
					t.Error("empty success")
				}
			}
		})
	}
	wg.Wait()
	if _, err := codec.Decode(wire); err != nil {
		t.Fatal("decoder not reusable after racing admission", err)
	}
}
