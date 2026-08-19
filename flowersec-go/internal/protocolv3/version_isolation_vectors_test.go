package protocolv3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	artifactv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/quicbase"
	rawquicv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/rawquicv3"
	websocketv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocketv3"
	webtransportv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/webtransportv3"
	internalhkdf "github.com/floegence/flowersec/flowersec-go/v3/internal/hkdf"
	gorillaws "github.com/gorilla/websocket"
)

type versionIsolationMutation struct {
	ID        string `json:"id"`
	V3        string `json:"v3"`
	V2        string `json:"v2"`
	ErrorCode string `json:"error_code"`
}

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
	ProfileMutations     []versionIsolationMutation `json:"profile_mutations"`
	PathMutations        []versionIsolationMutation `json:"path_mutations"`
	ALPNMutations        []versionIsolationMutation `json:"alpn_mutations"`
	CryptoLabelMutations []versionIsolationMutation `json:"crypto_label_mutations"`
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
				if err := ParseControlPreface(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { return ParseControlPreface(magic) })
				assertRejects(t, func() error { return ParseControlPreface(version) })
			case "fsh3":
				if _, err := ParseHandshakeFrame(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := ParseHandshakeFrame(magic); return err })
				assertRejects(t, func() error { _, err := ParseHandshakeFrame(version); return err })
			case "fss3":
				if _, err := ParseSetupPreface(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := ParseSetupPreface(magic); return err })
				assertRejects(t, func() error { _, err := ParseSetupPreface(version); return err })
			case "fsr3":
				if _, err := ParseRecordHeader(valid); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error { _, err := ParseRecordHeader(magic); return err })
				assertRejects(t, func() error { _, err := ParseRecordHeader(version); return err })
			case "fsd3":
				if _, err := ParseUnreliableHeader(valid[:UnreliableHeaderSize]); err != nil {
					t.Fatal(err)
				}
				assertRejects(t, func() error {
					_, err := ParseUnreliableHeader(magic[:UnreliableHeaderSize])
					return err
				})
				assertRejects(t, func() error {
					_, err := ParseUnreliableHeader(version[:UnreliableHeaderSize])
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
	_, err = ParseHandshakeFrame(mustHexIsolation(t, handshake.V3))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseClientInit(mustHexIsolation(t, handshake.V3)); err != nil {
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
	openPayload, err := MarshalOpenPayload(OpenPayload{LogicalStreamID: 1, Kind: openVector.Kind, Metadata: []byte(openVector.MetadataJSON)})
	if err != nil {
		t.Fatal(err)
	}
	decodedOpen, err := ParseOpenPayload(openPayload)
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

func TestVersionIsolationMutationsBindProductionBoundaries(t *testing.T) {
	fixture := loadVersionIsolationFixture(t)
	artifact := loadVersionIsolationArtifact(t)

	for _, mutation := range fixture.ProfileMutations {
		mutation := mutation
		t.Run("profile/"+mutation.ID, func(t *testing.T) {
			switch mutation.ID {
			case "session":
				if mutation.V3 != artifactv3.Profile {
					t.Fatalf("production profile = %q, vector = %q", artifactv3.Profile, mutation.V3)
				}
				valid := *artifact
				valid.Profile = mutation.V3
				if err := artifactv3.ValidateArtifact(valid); err != nil {
					t.Fatalf("v3 profile rejected: %v", err)
				}
				invalid := valid
				invalid.Profile = mutation.V2
				assertRejects(t, func() error { return artifactv3.ValidateArtifact(invalid) })
			case "direct", "tunnel":
				want := "flowersec-" + mutation.ID + "/3"
				if mutation.V3 != want {
					t.Fatalf("production wire profile = %q, vector = %q", want, mutation.V3)
				}
				candidate, kind := artifactCandidateWithProfile(*artifact, mutation.ID, mutation.V3)
				if _, _, _, err := artifactv3.CanonicalizeCandidates(kind, []artifactv3.Candidate{candidate}); err != nil {
					t.Fatalf("v3 wire profile rejected: %v", err)
				}
				candidate.WireProfile = mutation.V2
				assertRejects(t, func() error {
					_, _, _, err := artifactv3.CanonicalizeCandidates(kind, []artifactv3.Candidate{candidate})
					return err
				})
			default:
				t.Fatalf("unhandled profile mutation %q", mutation.ID)
			}
		})
	}

	for _, mutation := range fixture.PathMutations {
		mutation := mutation
		if strings.Contains(mutation.ID, "subprotocol") {
			continue
		}
		t.Run("path/"+mutation.ID, func(t *testing.T) {
			carrier, kind, scheme := versionIsolationPathMutation(mutation.ID)
			path := mutation.V3
			candidate := artifactv3.Candidate{
				ID: "path-" + mutation.ID, Carrier: carrier,
				URL:         scheme + "://example.test" + path,
				WireProfile: "flowersec-" + string(kind) + "/3",
				TLS:         artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA},
			}
			if _, _, _, err := artifactv3.CanonicalizeCandidates(kind, []artifactv3.Candidate{candidate}); err != nil {
				t.Fatalf("v3 path rejected by production canonicalizer: %v", err)
			}
			if carrier == artifactv3.CarrierWebTransport {
				if err := webtransportv3.ValidateURL(candidate.URL); err != nil {
					t.Fatalf("v3 WebTransport path rejected by production adapter: %v", err)
				}
			}
			candidate.URL = scheme + "://example.test" + mutation.V2
			assertRejects(t, func() error {
				_, _, _, err := artifactv3.CanonicalizeCandidates(kind, []artifactv3.Candidate{candidate})
				return err
			})
			if carrier == artifactv3.CarrierWebTransport {
				assertRejects(t, func() error { return webtransportv3.ValidateURL(candidate.URL) })
			}
		})
	}

	for _, mutation := range fixture.PathMutations {
		if !strings.Contains(mutation.ID, "subprotocol") {
			continue
		}
		mutation := mutation
		t.Run("websocket-subprotocol/"+mutation.ID, func(t *testing.T) {
			want := websocketv3.SubprotocolDirect
			if strings.Contains(mutation.ID, "tunnel") {
				want = websocketv3.SubprotocolTunnel
			}
			if mutation.V3 != want || mutation.V2 == want {
				t.Fatalf("subprotocol vector = (%q, %q), production = %q", mutation.V3, mutation.V2, want)
			}
			assertWebSocketCandidateProfile(t, mutation.V3, mutation.V2, want)
		})
	}

	for _, mutation := range fixture.ALPNMutations {
		mutation := mutation
		t.Run("alpn/"+mutation.ID, func(t *testing.T) {
			want := rawquicv3.ALPNDirect
			if mutation.ID == "tunnel" {
				want = rawquicv3.ALPNTunnel
			}
			if mutation.V3 != want || mutation.V2 == want {
				t.Fatalf("ALPN vector = (%q, %q), production = %q", mutation.V3, mutation.V2, want)
			}
			assertRawQUICCandidateProfile(t, mutation.V3, mutation.V2, want)
		})
	}

	seed := loadVersionIsolationCryptoSeed(t)
	for _, mutation := range fixture.CryptoLabelMutations {
		mutation := mutation
		t.Run("crypto-label/"+mutation.ID, func(t *testing.T) {
			got, want := bindVersionIsolationCryptoLabel(t, mutation.ID, mutation.V3, seed)
			if !bytes.Equal(got, want) {
				t.Fatalf("production %s label binding mismatch: got %x, want %x", mutation.ID, got, want)
			}
			_, legacyWant := bindVersionIsolationCryptoLabel(t, mutation.ID, mutation.V2, seed)
			if bytes.Equal(want, legacyWant) || bytes.Equal(got, legacyWant) {
				t.Fatalf("v2 %s label remained bound to the v3 output", mutation.ID)
			}
		})
	}
}

func loadVersionIsolationFixture(t *testing.T) versionIsolationFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v3/version_isolation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture versionIsolationFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func loadVersionIsolationArtifact(t *testing.T) *artifactv3.Artifact {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v3/artifact_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Positive []struct {
			ArtifactJSON string `json:"artifact_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Positive) == 0 {
		t.Fatalf("decode artifact fixture: %v", err)
	}
	artifact, err := artifactv3.DecodeArtifactJSON(strings.NewReader(fixture.Positive[0].ArtifactJSON))
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func artifactCandidateWithProfile(artifact artifactv3.Artifact, path, profile string) (artifactv3.Candidate, artifactv3.PathKind) {
	for _, candidate := range artifact.Path.Candidates {
		if candidate.Carrier == artifactv3.CarrierWebSocket {
			candidate.WireProfile = profile
			candidate.NormalizedURL = ""
			kind := artifactv3.PathDirect
			if path == "tunnel" {
				kind = artifactv3.PathTunnel
				candidate.URL = strings.Replace(candidate.URL, "/direct", "/tunnel", 1)
			}
			return candidate, kind
		}
	}
	panic("artifact fixture has no WebSocket candidate")
}

func versionIsolationPathMutation(id string) (artifactv3.Carrier, artifactv3.PathKind, string) {
	switch {
	case strings.HasPrefix(id, "websocket-"):
		kind := artifactv3.PathDirect
		if strings.Contains(id, "tunnel") {
			kind = artifactv3.PathTunnel
		}
		return artifactv3.CarrierWebSocket, kind, "wss"
	case strings.HasPrefix(id, "webtransport-"):
		kind := artifactv3.PathDirect
		if strings.Contains(id, "tunnel") {
			kind = artifactv3.PathTunnel
		}
		return artifactv3.CarrierWebTransport, kind, "https"
	default:
		panic("unknown version isolation path mutation " + id)
	}
}

func assertWebSocketCandidateProfile(t *testing.T, v3, v2, want string) {
	t.Helper()
	connections := make(chan *gorillaws.Conn, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := (&gorillaws.Upgrader{Subprotocols: []string{v3}}).Upgrade(writer, request, nil)
		if err == nil {
			connections <- conn
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	dialer := &gorillaws.Dialer{
		Subprotocols:    []string{v3},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true},
	}
	client, _, err := dialer.Dial(strings.Replace(server.URL, "https://", "wss://", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer := <-connections
	defer peer.Close()
	if err := websocketv3.ValidateReady(client, want); err != nil {
		t.Fatalf("production rejected v3 subprotocol %q: %v", v3, err)
	}
	if err := websocketv3.ValidateReady(client, v2); !errors.Is(err, websocketv3.ErrInvalidSubprotocol) {
		t.Fatalf("production accepted v2 subprotocol %q: %v", v2, err)
	}
}

func assertRawQUICCandidateProfile(t *testing.T, v3, v2, want string) {
	t.Helper()
	validTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{want}}
	if _, err := rawquicv3.Dial(context.Background(), "invalid", validTLS, quicbase.DefaultLimits()); errors.Is(err, rawquicv3.ErrInvalidALPN) {
		t.Fatalf("production rejected v3 ALPN %q: %v", v3, err)
	}
	legacyTLS := validTLS.Clone()
	legacyTLS.NextProtos = []string{v2}
	if _, err := rawquicv3.Dial(context.Background(), "invalid", legacyTLS, quicbase.DefaultLimits()); !errors.Is(err, rawquicv3.ErrInvalidALPN) {
		t.Fatalf("production accepted v2 ALPN %q: %v", v2, err)
	}
}

type versionIsolationCryptoSeed struct {
	SessionPRK [32]byte
	H3         [32]byte
	Direction  Direction
	Epoch      uint32
	StreamID   uint64
	Sequence   uint64
	Control    []byte
	ClientInit []byte
}

func loadVersionIsolationCryptoSeed(t *testing.T) versionIsolationCryptoSeed {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v3/crypto_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Direction  uint8  `json:"direction"`
			Epoch      uint32 `json:"epoch"`
			LogicalID  uint64 `json:"logical_stream_id"`
			Sequence   uint64 `json:"sequence"`
			SessionPRK string `json:"session_prk_hex"`
			H3         string `json:"h3_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Vectors) == 0 {
		t.Fatalf("decode crypto fixture: %v", err)
	}
	vector := fixture.Vectors[0]
	seed := versionIsolationCryptoSeed{Direction: Direction(vector.Direction), Epoch: vector.Epoch, StreamID: vector.LogicalID, Sequence: vector.Sequence}
	copy(seed.SessionPRK[:], mustHexIsolation(t, vector.SessionPRK))
	copy(seed.H3[:], mustHexIsolation(t, vector.H3))
	for _, frame := range loadVersionIsolationFixture(t).Frames {
		switch frame.ID {
		case "fsc3":
			seed.Control = mustHexIsolation(t, frame.V3)
		case "fsh3":
			seed.ClientInit = mustHexIsolation(t, frame.V3)
		}
	}
	return seed
}

func bindVersionIsolationCryptoLabel(t *testing.T, id, label string, seed versionIsolationCryptoSeed) ([]byte, []byte) {
	t.Helper()
	roots, err := DeriveEpochZero(seed.SessionPRK, seed.Direction)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := DeriveStreamMaterial(roots.StreamRoot, seed.H3, seed.StreamID, seed.Direction, seed.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	control, err := DeriveControlMaterial(roots.ControlRoot, seed.H3, seed.Direction, seed.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	unreliable, err := DeriveUnreliableMaterial(roots.EpochSecret, seed.H3, seed.Direction, seed.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	var expected func(string) []byte
	switch id {
	case "handshake":
		gotHash, err := ComputeHandshakeH0(seed.Control, seed.ClientInit)
		if err != nil {
			t.Fatal(err)
		}
		got = gotHash[:]
		expected = func(value string) []byte {
			digest := hashTranscript([]byte(value), seed.Control, lengthPrefixed(seed.ClientInit))
			return digest[:]
		}
	case "server-finished", "client-finished":
		var prk, transcript [32]byte
		prk = seed.SessionPRK
		transcript = seed.H3
		if id == "server-finished" {
			key, _, err := ComputeServerConfirm(prk, transcript)
			if err != nil {
				t.Fatal(err)
			}
			got = key[:]
		} else {
			key, _, err := ComputeClientConfirm(prk, transcript)
			if err != nil {
				t.Fatal(err)
			}
			got = key[:]
		}
		expected = func(value string) []byte {
			out, err := internalhkdf.ExpandSHA256(prk, append([]byte(value), transcript[:]...), 32)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
	case "epoch-zero":
		got = roots.EpochSecret[:]
		expected = func(value string) []byte {
			return mustExpand(t, seed.SessionPRK, labelWith(value, []byte{byte(seed.Direction)}))
		}
	case "control-root":
		got = roots.ControlRoot[:]
		expected = func(value string) []byte { return mustExpand(t, roots.EpochSecret, labelWith(value)) }
	case "stream-root":
		got = roots.StreamRoot[:]
		expected = func(value string) []byte { return mustExpand(t, roots.EpochSecret, labelWith(value)) }
	case "setup-root":
		got = roots.SetupMACRoot[:]
		expected = func(value string) []byte { return mustExpand(t, roots.EpochSecret, labelWith(value)) }
	case "rekey-root":
		got = roots.RekeyRoot[:]
		expected = func(value string) []byte { return mustExpand(t, roots.EpochSecret, labelWith(value)) }
	case "next-epoch":
		gotEpoch, err := DeriveNextEpoch(roots.RekeyRoot, seed.H3, seed.Direction, seed.Epoch+1)
		if err != nil {
			t.Fatal(err)
		}
		got = gotEpoch[:]
		expected = func(value string) []byte {
			var epoch [4]byte
			binary.BigEndian.PutUint32(epoch[:], seed.Epoch+1)
			return mustExpand(t, roots.RekeyRoot, labelWith(value, seed.H3[:], []byte{byte(seed.Direction)}, epoch[:]))
		}
	case "stream", "control":
		material := stream
		root := roots.StreamRoot
		logicalID := seed.StreamID
		if id == "control" {
			material = control
			root = roots.ControlRoot
			logicalID = 0
		}
		got = material.Secret[:]
		expected = func(value string) []byte {
			var logical, epoch [8]byte
			binary.BigEndian.PutUint64(logical[:], logicalID)
			binary.BigEndian.PutUint32(epoch[4:], seed.Epoch)
			return mustExpand(t, root, labelWith(value, seed.H3[:], logical[:], []byte{byte(seed.Direction)}, epoch[4:]))
		}
	case "record-key":
		got = stream.RecordKey[:]
		expected = func(value string) []byte { return mustExpand(t, stream.Secret, labelWith(value)) }
	case "nonce":
		got = stream.NoncePrefix[:]
		expected = func(value string) []byte { return mustExpandN(t, stream.Secret, labelWith(value), 4) }
	case "unreliable-root":
		got = unreliable.Root[:]
		expected = func(value string) []byte { return mustExpand(t, roots.EpochSecret, labelWith(value)) }
	case "unreliable":
		got = unreliable.Secret[:]
		expected = func(value string) []byte {
			return mustExpand(t, unreliable.Root, labelWith(value, seed.H3[:], []byte{byte(seed.Direction)}, uint32Bytes(seed.Epoch)))
		}
	case "unreliable-key":
		got = unreliable.RecordKey[:]
		expected = func(value string) []byte { return mustExpand(t, unreliable.Secret, labelWith(value)) }
	case "unreliable-nonce":
		got = unreliable.NoncePrefix[:]
		expected = func(value string) []byte { return mustExpandN(t, unreliable.Secret, labelWith(value), 4) }
	case "setup-mac":
		preface := SetupPreface{OpenerRole: RoleClient, LogicalStreamID: seed.StreamID, InitialEpoch: seed.Epoch}
		gotMAC, err := ComputeSetupMAC(roots.SetupMACRoot, seed.H3, preface)
		if err != nil {
			t.Fatal(err)
		}
		got = gotMAC[:]
		expected = func(value string) []byte {
			raw, err := preface.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			mac := hmac.New(sha256.New, roots.SetupMACRoot[:])
			_, _ = mac.Write([]byte(value))
			_, _ = mac.Write(seed.H3[:])
			_, _ = mac.Write(raw[:24])
			return mac.Sum(nil)
		}
	case "record-aad":
		header := RecordHeader{Epoch: seed.Epoch, Sequence: seed.Sequence, CiphertextLength: 19}
		raw, err := header.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got = recordAAD(seed.H3, seed.StreamID, seed.Direction, raw)
		expected = func(value string) []byte {
			out := append([]byte(value), seed.H3[:]...)
			out = append(out, make([]byte, 8)...)
			binary.BigEndian.PutUint64(out[len(value)+32:], seed.StreamID)
			out = append(out, byte(seed.Direction))
			return append(out, raw...)
		}
	case "unreliable-aad":
		header := UnreliableHeader{Epoch: seed.Epoch, Sequence: seed.Sequence, ExpiresAtUnixMS: 2_000_000_000_000, CiphertextLength: 19}
		plaintext := []byte("abc")
		ciphertext, err := SealUnreliable(SuiteChaCha20Poly1305, unreliable, seed.H3, seed.Direction, header, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		got = ciphertext
		expected = func(value string) []byte {
			raw, err := header.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			aead, err := newAEAD(SuiteChaCha20Poly1305, unreliable.RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			nonce := recordNonce(unreliable.NoncePrefix, header.Sequence)
			aad := labelWith(value, seed.H3[:], []byte{byte(seed.Direction)}, raw)
			return aead.Seal(nil, nonce[:], plaintext, aad)
		}
	case "open":
		payload, err := MarshalOpenPayload(OpenPayload{LogicalStreamID: 1, Kind: "stream", Metadata: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		gotHash, err := ComputeOpenHash(payload)
		if err != nil {
			t.Fatal(err)
		}
		got = gotHash[:]
		expected = func(value string) []byte {
			preimage := append([]byte(value), uint32Bytes(uint32(len(payload)))...)
			digest := sha256.Sum256(append(preimage, payload...))
			return digest[:]
		}
	default:
		t.Fatalf("unhandled crypto label mutation %q", id)
	}
	return got, expected(label)
}

func mustExpand(t *testing.T, prk [32]byte, info []byte) []byte { return mustExpandN(t, prk, info, 32) }

func mustExpandN(t *testing.T, prk [32]byte, info []byte, length int) []byte {
	t.Helper()
	out, err := internalhkdf.ExpandSHA256(prk, info, length)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func uint32Bytes(value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return raw[:]
}
