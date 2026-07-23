package rpc

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/observability"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
)

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
	firstClient := &Client{nextID: vectors.RequestIDGeneration.First, pending: make(map[uint64]chan rpcv1.RpcEnvelope)}
	first, _, err := firstClient.reserve()
	if err != nil || first != vectors.RequestIDGeneration.First {
		t.Fatalf("first request ID = %d, %v", first, err)
	}
	lastClient := &Client{nextID: vectors.RequestIDGeneration.Last, pending: make(map[uint64]chan rpcv1.RpcEnvelope)}
	last, _, err := lastClient.reserve()
	if err != nil || last != vectors.RequestIDGeneration.Last {
		t.Fatalf("last request ID = %d, %v", last, err)
	}
	lastClient.release(last)
	if _, _, err := lastClient.reserve(); err == nil {
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

func TestClientRequestIDUsesMaxSafeValueOnceThenFails(t *testing.T) {
	client := &Client{
		nextID:  maxPortableRequestID,
		pending: make(map[uint64]chan rpcv1.RpcEnvelope),
	}
	id, _, err := client.reserve()
	if err != nil {
		t.Fatal(err)
	}
	if id != maxPortableRequestID {
		t.Fatalf("request ID = %d", id)
	}
	client.release(id)
	if _, _, err := client.reserve(); err == nil {
		t.Fatal("expected request ID overflow")
	}
}

func TestClientRequestIDOverflowFailsBeforeWrite(t *testing.T) {
	transport := &countingReadWriteCloser{}
	client := &Client{
		r:       transport,
		nextID:  maxPortableRequestID + 1,
		pending: make(map[uint64]chan rpcv1.RpcEnvelope),
		notify:  make(map[uint32]map[*notifyHandler]struct{}),
		obs:     observability.NoopRPCObserver,
	}
	if _, _, err := client.Call(context.Background(), 1, json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected request ID overflow")
	}
	if transport.writes != 0 {
		t.Fatalf("transport writes = %d", transport.writes)
	}
}

type countingReadWriteCloser struct{ writes int }

func (*countingReadWriteCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (c *countingReadWriteCloser) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}
func (*countingReadWriteCloser) Close() error { return nil }
