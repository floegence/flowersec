package protocolv2_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	protocolv2 "github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

func TestOpenPayloadExactBinaryLayoutAndHashes(t *testing.T) {
	preface := protocolv2.SetupPreface{OpenerRole: protocolv2.RoleClient, LogicalStreamID: 1, InitialEpoch: 7}
	rawFSS2, err := preface.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fss2Hash, err := protocolv2.ComputeFSS2Hash(rawFSS2)
	if err != nil {
		t.Fatal(err)
	}
	if fss2Hash != sha256.Sum256(rawFSS2) {
		t.Fatal("FSS2 hash mismatch")
	}

	open := protocolv2.OpenPayload{
		LogicalStreamID: 1,
		FSS2Hash:        fss2Hash,
		Kind:            "rpc.echo",
		Metadata:        []byte(`{"a":[1,true],"z":"ok"}`),
	}
	raw, err := protocolv2.MarshalOpenPayload(open)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(raw[0:8]); got != 1 {
		t.Fatalf("logical id = %d", got)
	}
	if !bytes.Equal(raw[8:40], fss2Hash[:]) || binary.BigEndian.Uint16(raw[40:42]) != uint16(len(open.Kind)) || binary.BigEndian.Uint32(raw[42:46]) != uint32(len(open.Metadata)) {
		t.Fatalf("bad OPEN fixed fields: %x", raw[:46])
	}
	if string(raw[46:46+len(open.Kind)]) != open.Kind || !bytes.Equal(raw[46+len(open.Kind):], open.Metadata) {
		t.Fatal("bad OPEN variable fields")
	}
	decoded, err := protocolv2.ParseOpenPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.LogicalStreamID != open.LogicalStreamID || decoded.FSS2Hash != open.FSS2Hash || decoded.Kind != open.Kind || !bytes.Equal(decoded.Metadata, open.Metadata) {
		t.Fatalf("decoded OPEN = %+v", decoded)
	}

	gotOpenHash, err := protocolv2.ComputeOpenHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantOpenHash := labeledOpenHash(raw)
	if gotOpenHash != wantOpenHash {
		t.Fatalf("open hash = %x, want %x", gotOpenHash, wantOpenHash)
	}

	inner, err := protocolv2.MarshalInnerRecord(protocolv2.InnerOpen, raw)
	if err != nil {
		t.Fatal(err)
	}
	typ, payload, err := protocolv2.ParseInnerRecord(inner)
	if err != nil || typ != protocolv2.InnerOpen || !bytes.Equal(payload, raw) {
		t.Fatalf("inner OPEN round trip: type=%d error=%v", typ, err)
	}
}

func TestOpenEmptyMetadataCanonicalizesToObject(t *testing.T) {
	raw, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 1, Kind: "rpc", Metadata: nil})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocolv2.ParseOpenPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.Metadata) != "{}" {
		t.Fatalf("metadata = %q, want {}", decoded.Metadata)
	}
}

func TestOpenMetadataJCSDoesNotApplyHTMLEscaping(t *testing.T) {
	metadata := []byte(`{"html":"<>&"}`)
	raw, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 1, Kind: "rpc", Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocolv2.ParseOpenPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Metadata, metadata) {
		t.Fatalf("metadata = %s, want %s", decoded.Metadata, metadata)
	}
	if _, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 1, Kind: "rpc", Metadata: []byte(`{"html":"\u003c"}`)}); err == nil {
		t.Fatal("accepted noncanonical HTML escape")
	}
}

func TestOpenKindAndMetadataExactPositiveBounds(t *testing.T) {
	array := func(n int) string {
		values := make([]string, n)
		for i := range values {
			values[i] = "0"
		}
		return "[" + strings.Join(values, ",") + "]"
	}
	key64 := strings.Repeat("k", 64)
	metadata4096 := `{"a":"` + strings.Repeat("a", 512) + `","b":"` + strings.Repeat("b", 512) + `","c":"` + strings.Repeat("c", 512) + `","d":"` + strings.Repeat("d", 512) + `","e":"` + strings.Repeat("e", 512) + `","f":"` + strings.Repeat("f", 512) + `","g":"` + strings.Repeat("g", 512) + `","h":"` + strings.Repeat("h", 455) + `"}`
	if len(metadata4096) != protocolv2.MaxOpenMetadataBytes {
		t.Fatalf("4096-byte fixture length = %d", len(metadata4096))
	}
	keys64 := make([]string, 64)
	for i := range keys64 {
		keys64[i] = fmt.Sprintf("\"k%02d\":0", i)
	}
	tests := []struct {
		name     string
		kind     string
		metadata []byte
	}{
		{name: "kind 128", kind: strings.Repeat("k", 128), metadata: []byte(`{}`)},
		{name: "key 64 and string 512", kind: "rpc", metadata: []byte(`{"` + key64 + `":"` + strings.Repeat("s", 512) + `"}`)},
		{name: "array 32", kind: "rpc", metadata: []byte(`{"a":` + array(32) + `}`)},
		{name: "depth 4", kind: "rpc", metadata: []byte(`{"a":{"b":{"c":0}}}`)},
		{name: "nodes 64", kind: "rpc", metadata: []byte(`{"a":` + array(32) + `,"b":` + array(30) + `}`)},
		{name: "keys 64", kind: "rpc", metadata: []byte(`{` + strings.Join(keys64, ",") + `}`)},
		{name: "metadata 4096", kind: "rpc", metadata: []byte(metadata4096)},
		{name: "safe integers", kind: "rpc", metadata: []byte(`{"max":9007199254740991,"min":-9007199254740991}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 1, Kind: tt.kind, Metadata: tt.metadata}); err != nil {
				t.Fatalf("exact boundary rejected: %v", err)
			}
		})
	}
}

func TestOpenACKAndRejectExactPayloads(t *testing.T) {
	openHash := sha256.Sum256([]byte("open"))
	ack := protocolv2.MarshalOpenACK(openHash)
	if len(ack) != 32 || !bytes.Equal(ack, openHash[:]) {
		t.Fatalf("ACK = %x", ack)
	}
	parsedACK, err := protocolv2.ParseOpenACK(ack)
	if err != nil || parsedACK != openHash {
		t.Fatalf("parsed ACK = %x, error=%v", parsedACK, err)
	}

	reject, err := protocolv2.MarshalOpenReject(openHash, protocolv2.OpenRejectPolicyRejected)
	if err != nil {
		t.Fatal(err)
	}
	if len(reject) != 34 || binary.BigEndian.Uint16(reject[32:34]) != 3 {
		t.Fatalf("REJECT = %x", reject)
	}
	parsedReject, err := protocolv2.ParseOpenReject(reject)
	if err != nil || parsedReject.OpenHash != openHash || parsedReject.Reason != protocolv2.OpenRejectPolicyRejected || !parsedReject.KnownReason {
		t.Fatalf("parsed REJECT = %+v, error=%v", parsedReject, err)
	}

	unknown := append(append([]byte(nil), openHash[:]...), 0, 99)
	parsedUnknown, err := protocolv2.ParseOpenReject(unknown)
	if err != nil || parsedUnknown.Reason != 99 || parsedUnknown.KnownReason {
		t.Fatalf("unknown REJECT = %+v, error=%v", parsedUnknown, err)
	}
	if _, err := protocolv2.MarshalOpenReject(openHash, 99); err == nil {
		t.Fatal("sender accepted unregistered open reject reason")
	}
	if _, err := protocolv2.ParseOpenReject(append(append([]byte(nil), openHash[:]...), 0, 0)); err == nil {
		t.Fatal("receiver accepted reason zero")
	}
}

func TestOpenRejectsInvalidKindMetadataAndLengths(t *testing.T) {
	metadataWithKeys := func(n int) []byte {
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("\"k%02d\":0", i))
		}
		return []byte("{" + strings.Join(parts, ",") + "}")
	}
	array := func(n int) string {
		values := make([]string, n)
		for i := range values {
			values[i] = "0"
		}
		return "[" + strings.Join(values, ",") + "]"
	}
	nodeHeavy := []byte(`{"a":` + array(32) + `,"b":` + array(32) + `}`)
	tests := []struct {
		name     string
		kind     string
		metadata []byte
	}{
		{name: "empty kind", kind: "", metadata: []byte(`{}`)},
		{name: "kind 129", kind: strings.Repeat("k", 129), metadata: []byte(`{}`)},
		{name: "kind leading space", kind: " rpc", metadata: []byte(`{}`)},
		{name: "kind trailing space", kind: "rpc ", metadata: []byte(`{}`)},
		{name: "kind control", kind: "rpc\n", metadata: []byte(`{}`)},
		{name: "kind decomposed NFC", kind: "rpc-e\u0301", metadata: []byte(`{}`)},
		{name: "metadata nonobject", kind: "rpc", metadata: []byte(`[]`)},
		{name: "metadata duplicate", kind: "rpc", metadata: []byte(`{"a":1,"a":2}`)},
		{name: "metadata noncanonical order", kind: "rpc", metadata: []byte(`{"z":1,"a":2}`)},
		{name: "metadata whitespace", kind: "rpc", metadata: []byte(`{ "a":1}`)},
		{name: "metadata float", kind: "rpc", metadata: []byte(`{"a":1.5}`)},
		{name: "metadata exponent", kind: "rpc", metadata: []byte(`{"a":1e2}`)},
		{name: "metadata unsafe integer", kind: "rpc", metadata: []byte(`{"a":9007199254740992}`)},
		{name: "metadata nonminimal Unicode escape", kind: "rpc", metadata: []byte(`{"a":"\u00e9"}`)},
		{name: "metadata control", kind: "rpc", metadata: []byte(`{"a":"\u0001"}`)},
		{name: "metadata depth five", kind: "rpc", metadata: []byte(`{"a":{"b":{"c":{"d":0}}}}`)},
		{name: "metadata nodes 65", kind: "rpc", metadata: nodeHeavy},
		{name: "metadata object keys 65", kind: "rpc", metadata: metadataWithKeys(65)},
		{name: "metadata array 33", kind: "rpc", metadata: []byte(`{"a":` + array(33) + `}`)},
		{name: "metadata key 65", kind: "rpc", metadata: []byte(`{"` + strings.Repeat("k", 65) + `":0}`)},
		{name: "metadata string 513", kind: "rpc", metadata: []byte(`{"a":"` + strings.Repeat("s", 513) + `"}`)},
		{name: "metadata bytes 4097", kind: "rpc", metadata: []byte(`{"a":"` + strings.Repeat("s", 4_090) + `"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 1, Kind: tt.kind, Metadata: tt.metadata})
			if err == nil {
				t.Fatalf("MarshalOpenPayload accepted kind=%q metadata=%s", tt.kind, tt.metadata)
			}
		})
	}
	if _, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 0, Kind: "rpc", Metadata: []byte(`{}`)}); err == nil {
		t.Fatal("MarshalOpenPayload accepted logical id zero")
	}
	valid, err := protocolv2.MarshalOpenPayload(protocolv2.OpenPayload{LogicalStreamID: 1, Kind: "rpc", Metadata: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{valid[:45], append(valid, 0), func() []byte {
		copy := append([]byte(nil), valid...)
		binary.BigEndian.PutUint32(copy[42:46], 99)
		return copy
	}()} {
		if _, err := protocolv2.ParseOpenPayload(raw); err == nil {
			t.Fatalf("ParseOpenPayload accepted malformed bytes %x", raw)
		}
	}
	if _, err := protocolv2.ComputeFSS2Hash(make([]byte, 55)); err == nil {
		t.Fatal("ComputeFSS2Hash accepted non-FSS2 bytes")
	}
}

func labeledOpenHash(payload []byte) [32]byte {
	preimage := make([]byte, 0, len("flowersec-v2-open\x00")+4+len(payload))
	preimage = append(preimage, "flowersec-v2-open\x00"...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	preimage = append(preimage, size[:]...)
	preimage = append(preimage, payload...)
	return sha256.Sum256(preimage)
}

func requireStreamProtocolError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, protocolv2.ErrStreamProtocol) {
		t.Fatalf("error = %v, want stream protocol error", err)
	}
}
