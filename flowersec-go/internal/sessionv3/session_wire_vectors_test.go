package sessionv3

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedSessionWireV3Vectors(t *testing.T) {
	var fixture struct {
		Version            int    `json:"version"`
		Profile            string `json:"profile"`
		StreamKeyUpdateACK []struct {
			LogicalIDHex    string `json:"logical_id_hex"`
			TransitionIDHex string `json:"transition_id_hex"`
			NextEpochHex    string `json:"next_epoch_hex"`
			PayloadHex      string `json:"payload_hex"`
		} `json:"stream_key_update_ack"`
	}
	raw, err := os.ReadFile("../../../testdata/transport_v3/session_wire_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 3 || fixture.Profile != "flowersec/3" || len(fixture.StreamKeyUpdateACK) == 0 {
		t.Fatalf("invalid v3 session wire fixture header: version=%d profile=%q vectors=%d", fixture.Version, fixture.Profile, len(fixture.StreamKeyUpdateACK))
	}
	for index, vector := range fixture.StreamKeyUpdateACK {
		logicalID := decodeVectorUint(t, vector.LogicalIDHex, 8)
		transitionID := decodeVectorUint(t, vector.TransitionIDHex, 8)
		nextEpoch := decodeVectorUint(t, vector.NextEpochHex, 4)
		payload, err := hex.DecodeString(vector.PayloadHex)
		if err != nil {
			t.Fatalf("vector %d payload: %v", index, err)
		}
		encoded := marshalStreamKeyUpdateACK(logicalID, transitionID, uint32(nextEpoch))
		if !bytes.Equal(encoded[:], payload) {
			t.Fatalf("vector %d payload = %x, want %x", index, encoded, payload)
		}
		gotLogicalID, gotTransitionID, gotNextEpoch, err := parseStreamKeyUpdateACK(payload)
		if err != nil || gotLogicalID != logicalID || gotTransitionID != transitionID || uint64(gotNextEpoch) != nextEpoch {
			t.Fatalf("vector %d decode = (%d,%d,%d,%v)", index, gotLogicalID, gotTransitionID, gotNextEpoch, err)
		}
	}
}

func decodeVectorUint(t *testing.T, value string, bytes int) uint64 {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != bytes {
		t.Fatalf("decode %q as %d-byte integer: length=%d error=%v", value, bytes, len(decoded), err)
	}
	var result uint64
	for _, current := range decoded {
		result = result<<8 | uint64(current)
	}
	return result
}
