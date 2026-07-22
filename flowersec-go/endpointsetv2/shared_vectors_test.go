package endpointsetv2

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSharedEndpointSetVectors(t *testing.T) {
	var fixture struct {
		Version int `json:"version"`
		Valid   []struct {
			Name          string `json:"name"`
			NowUnix       int64  `json:"now_unix_s"`
			CanonicalJSON string `json:"canonical_json"`
		} `json:"valid"`
		Invalid []struct {
			Name    string `json:"name"`
			NowUnix int64  `json:"now_unix_s"`
			JSON    string `json:"json"`
		} `json:"invalid"`
	}
	raw, err := os.ReadFile("../../testdata/transport_v2/endpoint_set_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Valid) == 0 || len(fixture.Invalid) == 0 {
		t.Fatal("endpoint-set vectors are incomplete")
	}
	for _, vector := range fixture.Valid {
		t.Run("valid/"+vector.Name, func(t *testing.T) {
			set, err := DecodeJSON(bytes.NewBufferString(vector.CanonicalJSON), time.Unix(vector.NowUnix, 0))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := MarshalJSON(*set, time.Unix(vector.NowUnix, 0))
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != vector.CanonicalJSON {
				t.Fatalf("canonical JSON = %s, want %s", encoded, vector.CanonicalJSON)
			}
		})
	}
	for _, vector := range fixture.Invalid {
		t.Run("invalid/"+vector.Name, func(t *testing.T) {
			if _, err := DecodeJSON(bytes.NewBufferString(vector.JSON), time.Unix(vector.NowUnix, 0)); err == nil {
				t.Fatal("invalid endpoint set was accepted")
			}
		})
	}
}
