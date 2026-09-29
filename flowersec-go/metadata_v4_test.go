package flowersec

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestMetadataPreservesApplicationEnvelope(t *testing.T) {
	input := map[string][]byte{"token": {0xff, 0, 0xfe}}
	metadata, err := NewStreamMetadataEnvelope("example/binary", 7, input)
	if err != nil {
		t.Fatal(err)
	}
	wire := metadata.Bytes()
	input["token"][0] = 0
	accepted, err := streamMetadataFromV4Bytes(wire)
	if err != nil || accepted.Namespace() != "example/binary" || accepted.Version() != 7 || !bytes.Equal(accepted.ByteValues()["token"], []byte{0xff, 0, 0xfe}) {
		t.Fatal("application bytes or envelope changed", err)
	}
	values := accepted.ByteValues()
	values["token"][0] = 0
	wire[0] = 0
	if !bytes.Equal(metadata.Bytes(), accepted.Bytes()) || accepted.ByteValues()["token"][0] != 0xff {
		t.Fatal("metadata retained caller storage")
	}
	if _, err := accepted.JSONValues(); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatal("unknown application codec was interpreted as JSON", err)
	}
	for _, namespace := range []string{"application", "flowersec/private", "Example/binary"} {
		if _, err := NewStreamMetadataEnvelope(namespace, 1, input); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatal("invalid namespace admitted", namespace, err)
		}
	}
}

func TestMetadataJSONUsesValidCurrentShell(t *testing.T) {
	metadata, err := NewStreamMetadata(map[string]any{"fraction": 1.5, "integer": json.Number("9007199254740992")})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := streamMetadataFromV4Bytes(metadata.Bytes())
	if err != nil || accepted.Namespace() != "application/json" || accepted.Version() != 1 {
		t.Fatal("ordinary OPEN rejected emitted metadata", err)
	}
	values, err := accepted.JSONValues()
	if err != nil || values["fraction"] != json.Number("1.5") || values["integer"] != json.Number("9007199254740992") {
		t.Fatal("JSON value bytes were changed", values, err)
	}
	metadata, err = NewStreamMetadata(nil)
	if err != nil || len(metadata.Bytes()) != 0 || metadata.Namespace() != "" || len(metadata.ByteValues()) != 0 {
		t.Fatal("empty metadata has a second wire representation", err)
	}
}
