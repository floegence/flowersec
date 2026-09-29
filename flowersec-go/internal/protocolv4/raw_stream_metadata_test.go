package protocolv4

import (
	"reflect"
	"testing"
)

func TestRawStreamMetadataContractProjectionPreservesEnvelope(t *testing.T) {
	wire, err := EncodeStreamMetadataEnvelope(StreamMetadataEnvelope{
		Namespace: "application/json", Version: 1,
		Values: map[string][]byte{"message": []byte(`"hello"`), "count": []byte(`2`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	contract, err := (RawStreamMetadataContract{
		ContractID: "code.raw.v1", Namespace: "application/json", Version: 1,
		Fields: []RawStreamMetadataField{{Name: "message", Type: RawStreamMetadataString, Required: true}, {Name: "count", Type: RawStreamMetadataNumber}},
	}).Capture()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contract.Project(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projection, map[string]any{"message": "hello", "count": float64(2)}) {
		t.Fatalf("projection=%#v", projection)
	}
	rebuilt, err := DecodeStreamMetadataEnvelope(wire)
	if err != nil || string(rebuilt.Values["message"]) != `"hello"` {
		t.Fatalf("wire changed: %v %#v", err, rebuilt.Values)
	}
}

func TestRawStreamMetadataContractRejectsShapeAndDecodedBudget(t *testing.T) {
	wire, err := EncodeStreamMetadataEnvelope(StreamMetadataEnvelope{Namespace: "application/json", Version: 1, Values: map[string][]byte{"message": []byte(`true`)}})
	if err != nil {
		t.Fatal(err)
	}
	contract, err := (RawStreamMetadataContract{ContractID: "code.raw.v1", Namespace: "application/json", Version: 1, Fields: []RawStreamMetadataField{{Name: "message", Type: RawStreamMetadataString}}}).Capture()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Project(wire); err == nil {
		t.Fatal("expected type rejection")
	}
	contract.Fields[0].Type = RawStreamMetadataString
	contract.MaxDecodedBytes = 2
	wire, err = EncodeStreamMetadataEnvelope(StreamMetadataEnvelope{Namespace: "application/json", Version: 1, Values: map[string][]byte{"message": []byte(`"x"`)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Project(wire); err == nil {
		t.Fatal("expected decoded budget rejection")
	}
}
