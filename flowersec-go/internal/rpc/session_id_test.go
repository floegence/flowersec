package rpc

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf8"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/v7/internal/rpcwire"
)

func TestDecodeEnvelopeRPCErrorInvariant(t *testing.T) {
	makeEnvelope := func(t *testing.T, rpcError any) []byte {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"type_id": 1, "request_id": 0, "response_to": 1,
			"payload": map[string]any{}, "error": rpcError,
		})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	validASCII := string(make([]byte, 1024))
	validMultibyte := "é"
	for len(validMultibyte) < 1024 {
		validMultibyte += "é"
	}
	for name, value := range map[string][]byte{
		"missing message": makeEnvelope(t, map[string]any{"code": 1}),
		"ascii 1024":      makeEnvelope(t, map[string]any{"code": 1, "message": validASCII}),
		"multibyte 1024":  makeEnvelope(t, map[string]any{"code": 1, "message": validMultibyte}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeEnvelope(value); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalidUTF8 := []byte(`{"type_id":1,"request_id":0,"response_to":1,"payload":{},"error":{"code":1,"message":"`)
	invalidUTF8 = append(invalidUTF8, 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}}`)...)
	if utf8.Valid(invalidUTF8) {
		t.Fatal("invalid UTF-8 fixture is valid")
	}
	for name, value := range map[string][]byte{
		"zero code":          makeEnvelope(t, map[string]any{"code": 0}),
		"ascii 1025":         makeEnvelope(t, map[string]any{"code": 1, "message": validASCII + "a"}),
		"multibyte 1026":     makeEnvelope(t, map[string]any{"code": 1, "message": validMultibyte + "é"}),
		"extra error field":  makeEnvelope(t, map[string]any{"code": 1, "internal": "secret"}),
		"invalid UTF-8 text": invalidUTF8,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeEnvelope(value); err == nil {
				t.Fatal("accepted invalid RPC error")
			}
		})
	}
}

func TestDecodeEnvelopePortableRequestIDBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "zero", value: "0", valid: true},
		{name: "one", value: "1", valid: true},
		{name: "max safe", value: "9007199254740991", valid: true},
		{name: "over max safe", value: "9007199254740992"},
		{name: "negative", value: "-1"},
		{name: "fractional", value: "1.5"},
		{name: "string", value: `"1"`},
		{name: "boolean", value: "true"},
		{name: "null", value: "null"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, field := range []string{"request_id", "response_to"} {
				envelope := map[string]json.RawMessage{
					"type_id":     json.RawMessage("1"),
					"request_id":  json.RawMessage("0"),
					"response_to": json.RawMessage("0"),
					"payload":     json.RawMessage(`{}`),
				}
				envelope[field] = json.RawMessage(test.value)
				data, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				_, err = decodeEnvelope(data)
				if test.valid && err != nil {
					t.Fatalf("%s rejected: %v", field, err)
				}
				if !test.valid && err == nil {
					t.Fatalf("%s accepted invalid value %s", field, test.value)
				}
			}
		})
	}
}

func TestDecodeEnvelopeSharedRuntimeVectors(t *testing.T) {
	var vectors struct {
		Version                int    `json:"version"`
		MaxPortableJSONInteger uint64 `json:"max_portable_json_integer"`
		RPCJSONIntegers        []struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"rpc_json_integers"`
		RequestIDGeneration struct {
			First     uint64 `json:"first"`
			Last      uint64 `json:"last"`
			AfterLast string `json:"after_last"`
		} `json:"request_id_generation"`
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "testdata/runtime_contract_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 || vectors.MaxPortableJSONInteger != maxPortableRequestID {
		t.Fatalf("unexpected contract header: %+v", vectors)
	}
	if vectors.RequestIDGeneration.First != 1 ||
		vectors.RequestIDGeneration.Last != maxPortableRequestID ||
		vectors.RequestIDGeneration.AfterLast != "fail_before_write" {
		t.Fatalf("unexpected request ID generation contract: %+v", vectors.RequestIDGeneration)
	}
	firstClient := &Client{nextID: vectors.RequestIDGeneration.First, pending: make(map[uint64]pendingCall)}
	first, _, err := firstClient.reserve(1)
	if err != nil || first != vectors.RequestIDGeneration.First {
		t.Fatalf("first request ID = %d, %v", first, err)
	}
	lastClient := &Client{nextID: vectors.RequestIDGeneration.Last, pending: make(map[uint64]pendingCall)}
	last, _, err := lastClient.reserve(1)
	if err != nil || last != vectors.RequestIDGeneration.Last {
		t.Fatalf("last request ID = %d, %v", last, err)
	}
	lastClient.release(last)
	if _, _, err := lastClient.reserve(1); err == nil {
		t.Fatal("request ID generation did not fail after the portable maximum")
	}
	for _, test := range vectors.RPCJSONIntegers {
		t.Run(test.ID, func(t *testing.T) {
			envelope := []byte(`{"type_id":1,"request_id":0,"response_to":` + string(test.Value) + `,"payload":{}}`)
			_, err := decodeEnvelope(envelope)
			if test.Valid && err != nil {
				t.Fatal(err)
			}
			if !test.Valid && err == nil {
				t.Fatalf("accepted invalid value %s", test.Value)
			}
		})
	}
}

func TestDecodeEnvelopeRequiresPortableIDFields(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"type_id":1,"response_to":0,"payload":{}}`),
		[]byte(`{"type_id":1,"request_id":0,"payload":{}}`),
	} {
		if _, err := decodeEnvelope(data); err == nil {
			t.Fatalf("accepted envelope with missing ID: %s", data)
		}
	}
}

func TestDecodeEnvelopeSharedMalformedVectors(t *testing.T) {
	var vectors struct {
		TransportContractVersion int `json:"transport_contract_version"`
		Version                  int `json:"version"`
		Vectors                  []struct {
			ID       string          `json:"id"`
			Valid    bool            `json:"valid"`
			Envelope json.RawMessage `json:"envelope"`
		} `json:"vectors"`
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "testdata/transport_v5/rpc_malformed_envelopes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 || vectors.TransportContractVersion != 5 || len(vectors.Vectors) == 0 {
		t.Fatalf("unexpected malformed envelope vectors: version=%d contract=%d count=%d", vectors.Version, vectors.TransportContractVersion, len(vectors.Vectors))
	}
	for _, vector := range vectors.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			_, err := decodeEnvelope(vector.Envelope)
			if vector.Valid && err != nil {
				t.Fatalf("valid envelope rejected: %v", err)
			}
			if !vector.Valid && err == nil {
				t.Fatal("malformed envelope accepted")
			}
		})
	}
}

func TestClientRequestIDUsesMaxSafeValueOnceThenFails(t *testing.T) {
	client := &Client{
		nextID:  maxPortableRequestID,
		pending: make(map[uint64]pendingCall),
	}
	id, _, err := client.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	if id != maxPortableRequestID {
		t.Fatalf("request ID = %d", id)
	}
	client.release(id)
	if _, _, err := client.reserve(1); err == nil {
		t.Fatal("expected request ID overflow")
	}
}

func TestClientRequestIDOverflowFailsBeforeWrite(t *testing.T) {
	transport := &countingReadWriteCloser{}
	client := &Client{
		r:       transport,
		nextID:  maxPortableRequestID + 1,
		pending: make(map[uint64]pendingCall),
		notify:  make(map[uint32]map[*notifyHandler]struct{}),
	}
	if _, _, err := client.Call(context.Background(), 1, json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected request ID overflow")
	}
	if transport.writes != 0 {
		t.Fatalf("transport writes = %d", transport.writes)
	}
}

func TestResponseMustMatchLiveRequestMethod(t *testing.T) {
	client := &Client{nextID: 1, pending: make(map[uint64]pendingCall)}
	first, reply, err := client.reserve(7001)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := client.reserve(7002)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.deliverResponse(rpcv1.RpcEnvelope{ResponseTo: first, TypeId: 7002}); err == nil || len(reply) != 0 {
		t.Fatal("a reply for a different method must fail without delivering a result")
	}
	client.release(second)
	if err := client.deliverResponse(rpcv1.RpcEnvelope{ResponseTo: second, TypeId: 7002}); err != nil {
		t.Fatalf("late reply after cancellation: %v", err)
	}
	if err := client.deliverResponse(rpcv1.RpcEnvelope{ResponseTo: first, TypeId: 7001}); err != nil || len(reply) != 1 {
		t.Fatal("a matching reply was not delivered")
	}
	<-reply
	if err := client.deliverResponse(rpcv1.RpcEnvelope{ResponseTo: first, TypeId: 7001}); err != nil || len(reply) != 0 {
		t.Fatal("a completed request must not receive a second reply")
	}
}

type countingReadWriteCloser struct{ writes int }

func (*countingReadWriteCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (c *countingReadWriteCloser) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}
func (*countingReadWriteCloser) Close() error { return nil }
