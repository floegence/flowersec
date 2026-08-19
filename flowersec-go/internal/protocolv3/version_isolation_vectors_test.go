package protocolv3_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	artifactv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	protocolv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
)

type versionIsolationFixture struct {
	Version int `json:"version"`
	Frames  []struct {
		ID        string `json:"id"`
		V3        string `json:"v3_hex"`
		V2Magic   string `json:"v2_magic_hex"`
		V2Version string `json:"v2_version_hex"`
	} `json:"frames"`
	Inherited struct {
		FSH3 struct {
			FrameID string `json:"frame_id"`
		} `json:"fsh3"`
		Open struct {
			VectorID string `json:"vector_id"`
		} `json:"open"`
		RPC struct {
			Envelope string `json:"envelope_json"`
		} `json:"rpc"`
	} `json:"inherited_codecs"`
}

func TestVersionIsolationFramesFailClosedAcrossProductionDecoders(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/version_isolation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture versionIsolationFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 3 || len(fixture.Frames) != 7 {
		t.Fatalf("unexpected fixture: %+v", fixture)
	}
	for _, vector := range fixture.Frames {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			valid := mustHexIsolation(t, vector.V3)
			magic := mustHexIsolation(t, vector.V2Magic)
			version := mustHexIsolation(t, vector.V2Version)
			switch vector.ID {
			case "fsb3":
				if _, err := artifactv3.ParseRequest(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := artifactv3.ParseRequest(magic); return err })
				assertRejects(t, func() error { _, err := artifactv3.ParseRequest(version); return err })
			case "fsa3":
				if _, err := artifactv3.ParseClientResponse(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := artifactv3.ParseClientResponse(magic); return err })
				assertRejects(t, func() error { _, err := artifactv3.ParseClientResponse(version); return err })
			case "fsc3":
				if err := protocolv3.ParseControlPreface(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { return protocolv3.ParseControlPreface(magic) })
				assertRejects(t, func() error { return protocolv3.ParseControlPreface(version) })
			case "fsh3":
				if _, err := protocolv3.ParseHandshakeFrame(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := protocolv3.ParseHandshakeFrame(magic); return err })
				assertRejects(t, func() error { _, err := protocolv3.ParseHandshakeFrame(version); return err })
			case "fss3":
				if _, err := protocolv3.ParseSetupPreface(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := protocolv3.ParseSetupPreface(magic); return err })
				assertRejects(t, func() error { _, err := protocolv3.ParseSetupPreface(version); return err })
			case "fsr3":
				if _, err := protocolv3.ParseRecordHeader(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := protocolv3.ParseRecordHeader(magic); return err })
				assertRejects(t, func() error { _, err := protocolv3.ParseRecordHeader(version); return err })
			case "fsd3":
				if _, err := protocolv3.ParseUnreliableHeader(valid[:protocolv3.UnreliableHeaderSize]); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error {
					_, err := protocolv3.ParseUnreliableHeader(magic[:protocolv3.UnreliableHeaderSize])
					return err
				})
				assertRejects(t, func() error {
					_, err := protocolv3.ParseUnreliableHeader(version[:protocolv3.UnreliableHeaderSize])
					return err
				})
			}
		})
	}
}

func TestVersionIsolationInheritedCodecsUseV3ProductionBoundaries(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/version_isolation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture versionIsolationFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var handshake struct {
		V3 string `json:"v3_hex"`
	}
	for _, frame := range fixture.Frames {
		if frame.ID == "fsh3" {
			handshake.V3 = frame.V3
		}
	}
	_, err = protocolv3.ParseHandshakeFrame(mustHexIsolation(t, handshake.V3))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocolv3.ParseClientInit(mustHexIsolation(t, handshake.V3)); err != nil {
		t.Fatal(err)
	}
	openRaw, err := os.ReadFile("../../../testdata/transport_v3/open_unicode_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var openFixture struct {
		Positive []struct {
			ID           string `json:"id"`
			Kind         string `json:"kind"`
			MetadataJSON string `json:"metadata_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(openRaw, &openFixture); err != nil {
		t.Fatal(err)
	}
	var openVector struct{ Kind, MetadataJSON string }
	for _, vector := range openFixture.Positive {
		if vector.ID == fixture.Inherited.Open.VectorID {
			openVector.Kind, openVector.MetadataJSON = vector.Kind, vector.MetadataJSON
		}
	}
	if openVector.Kind == "" {
		t.Fatal("missing OPEN vector")
	}
	openPayload, err := protocolv3.MarshalOpenPayload(protocolv3.OpenPayload{LogicalStreamID: 1, Kind: openVector.Kind, Metadata: []byte(openVector.MetadataJSON)})
	if err != nil {
		t.Fatal(err)
	}
	decodedOpen, err := protocolv3.ParseOpenPayload(openPayload)
	if err != nil || decodedOpen.Kind != openVector.Kind || string(decodedOpen.Metadata) != openVector.MetadataJSON {
		t.Fatalf("OPEN codec mismatch: %v", err)
	}
	// The dedicated OPEN vector suite supplies the inherited non-JCS session codec;
	// this assertion keeps the isolation fixture tied to that reviewed vector ID.
	if fixture.Inherited.Open.VectorID != "minimal-string-escaping" {
		t.Fatal("unexpected OPEN vector")
	}
	if fixture.Inherited.RPC.Envelope == "" {
		t.Fatal("missing RPC envelope")
	}
	if !bytes.Contains([]byte(fixture.Inherited.RPC.Envelope), []byte(`"ratio":1.5`)) {
		t.Fatal("RPC float domain missing")
	}
}

func mustHexIsolation(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func assertRejects(t *testing.T, decode func() error) {
	t.Helper()
	if err := decode(); err == nil {
		t.Fatal("v2 mutation accepted")
	}
}
