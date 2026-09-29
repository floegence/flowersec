package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func topUpEncode(t *testing.T, schema string, fields []Field) []byte {
	t.Helper()
	wire, err := EncodeMap(make([]byte, 524288), schema, fields)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func topUpProof(t *testing.T, r TopUpRequestFacts, generation uint64) ([]byte, TopUpFenceAuthority) {
	t.Helper()
	seed := [32]byte{7}
	key := ed25519.NewKeyFromSeed(seed[:])
	authority := TopUpFenceAuthority{KeyID: [16]byte{8}, PublicKey: [32]byte(key.Public().(ed25519.PublicKey))}
	codec, err := NewSignedMapCodec("OwnerFenceProof", 512, 64)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Sign([]Field{
		{Name: "tenant_id", Kind: TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: ByteString, Bytes: r.Source[:]}, {Name: "operation_id", Kind: ByteString, Bytes: r.Operation[:]}, {Name: "request_digest", Kind: ByteString, Bytes: r.Digest[:]}, {Name: "current_generation", Number: generation}, {Name: "issued_at_ms", Number: 100}, {Name: "expires_at_ms", Number: 500}, {Name: "authority_key_id", Kind: ByteString, Bytes: authority.KeyID[:]},
	}, seed, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Release()
	wire, err := signed.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(wire), authority
}
func topUpRequestFields(r TopUpRequestFacts, proof []byte) []Field {
	return []Field{
		{Name: "operation_id", Kind: ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: ByteString, Bytes: r.Source[:]}, {Name: "desired_count", Number: uint64(r.DesiredCount)}, {Name: "max_item_bytes", Number: uint64(r.MaxItemBytes)}, {Name: "pool_digest", Kind: ByteString, Bytes: r.Pool[:]}, {Name: "binding_generation", Number: r.Generation}, {Name: "owner_fence_proof", Kind: ByteString, Bytes: proof}, {Name: "request_deadline_ms", Number: r.DeadlineMS}, {Name: "client_identity_digest", Kind: ByteString, Bytes: r.Identity[:]},
	}
}
func topUpFixture(t *testing.T) (TopUpRequestFacts, []byte, TopUpFenceAuthority) {
	t.Helper()
	r := TopUpRequestFacts{Tenant: "tenant-1", Source: [16]byte{2}, Pool: [32]byte{3}, Identity: [32]byte{4}, Generation: 1, DeadlineMS: 400, DesiredCount: 2, MaxItemBytes: 64}
	binary.BigEndian.PutUint64(r.Operation[:8], 1)
	r.Operation[8] = 9
	proof, authority := topUpProof(t, r, 1)
	wire := topUpEncode(t, "TopUpRequest", topUpRequestFields(r, proof))
	decoder, _ := NewDecoder(524288, 256)
	doc, err := decoder.DecodeShape(wire, "TopUpRequest", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	r.Digest, err = rawTopUpDigest(doc, make([]byte, 524288), "topup_request_digest")
	doc.Release()
	if err != nil {
		t.Fatal(err)
	}
	proof, _ = topUpProof(t, r, 1)
	return r, topUpEncode(t, "TopUpRequest", topUpRequestFields(r, proof)), authority
}
func topUpResponseFixture(t *testing.T, r TopUpRequestFacts, generation, first uint64, gap bool, retired uint64) ([]byte, TopUpResponseFacts) {
	t.Helper()
	array := []byte{0x82}
	f := TopUpResponseFacts{Tenant: r.Tenant, Source: r.Source, Operation: r.Operation, Generation: generation, Highest: first + 1, Gap: gap, RetiredThrough: retired, Count: 2}
	for i := range 2 {
		material := []byte{0xa1, 0x00, byte(i)}
		digest := sha256.Sum256(material)
		item := TopUpEntryFacts{Sequence: first + uint64(i), Generation: generation, ExpiryMS: 1000, Material: digest, Identity: r.Identity}
		f.Entries[i] = item
		entry := topUpEncode(t, "TopUpEntry", []Field{{Name: "artifact_sequence", Number: item.Sequence}, {Name: "binding_generation", Number: item.Generation}, {Name: "expiry_ms", Number: item.ExpiryMS}, {Name: "material", Kind: ByteString, Bytes: material}, {Name: "material_digest", Kind: ByteString, Bytes: digest[:]}, {Name: "client_identity_digest", Kind: ByteString, Bytes: r.Identity[:]}})
		array = append(array, entry...)
	}
	fields := []Field{{Name: "operation_id", Kind: ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: ByteString, Bytes: r.Source[:]}, {Name: "binding_generation", Number: generation}, {Name: "entries", Kind: EncodedArray, Bytes: array}, {Name: "server_highest_artifact_sequence", Number: f.Highest}, {Name: "gap_authorized", Kind: Boolean}, {Name: "server_committed", Kind: Boolean, Number: 1}, {Name: "response_digest", Kind: ByteString, Bytes: f.Digest[:]}}
	if gap {
		fields[6].Number = 1
		fields = append(fields, Field{Name: "retired_artifact_through", Number: retired})
	}
	wire := topUpEncode(t, "TopUpResponse", fields)
	decoder, _ := NewDecoder(524288, 256)
	doc, err := decoder.DecodeShape(wire, "TopUpResponse", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	f.Digest, err = rawTopUpDigest(doc, make([]byte, 524288), "topup_response_digest")
	doc.Release()
	if err != nil {
		t.Fatal(err)
	}
	fields[8].Bytes = f.Digest[:]
	return topUpEncode(t, "TopUpResponse", fields), f
}

func TestTopUpRuntimeRawDigestsMatchIndependentCorpus(t *testing.T) {
	count := 0
	for _, v := range domainFixtures(t) {
		schema, key := "", ""
		switch v.Domain {
		case "topup_request_digest":
			schema, key = "TopUpRequest", "request"
		case "topup_response_digest":
			schema, key = "TopUpResponse", "response"
		default:
			continue
		}
		if v.ExpectedError != "" {
			continue
		}
		wire := v.args(t)[key].([]byte)
		d, _ := NewDecoder(524288, 256)
		doc, err := d.DecodeShape(wire, schema, DecodeContext{})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := rawTopUpDigest(doc, make([]byte, 524288), v.Domain)
		doc.Release()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(digest[:], domainHex(t, v.Result.Output)) {
			t.Fatalf("%s digest drift", v.ID)
		}
		count++
	}
	if count < 2 {
		t.Fatal("missing independent raw projection vectors")
	}
}

func TestTopUpRuntimeProofBindingAndRecoveryGeneration(t *testing.T) {
	want, wire, authority := topUpFixture(t)
	codec, err := NewTopUpCodec()
	if err != nil {
		t.Fatal(err)
	}
	now := timev4.Interval{LowerMS: 200, UpperMS: 201}
	got, err := codec.ParseRequest(wire, authority, now)
	if err != nil || got != want {
		t.Fatalf("request: %+v %v", got, err)
	}
	proof, _ := topUpProof(t, want, 2)
	renewed := want
	renewed.Generation = 2
	updated := topUpEncode(t, "TopUpRequest", topUpRequestFields(renewed, proof))
	got, err = codec.ParseRequest(updated, authority, now)
	if err != nil || got.Digest != want.Digest || got.Generation != 2 {
		t.Fatal("fence renewal altered intent", err)
	}
	for _, name := range []string{"intent", "authority", "proof", "expired"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(wire)
			key := authority
			time := now
			switch name {
			case "intent":
				changed := want
				changed.DesiredCount = 1
				p, _ := topUpProof(t, want, 1)
				data = topUpEncode(t, "TopUpRequest", topUpRequestFields(changed, p))
			case "authority":
				key.KeyID[0] ^= 1
			case "proof":
				data[len(data)-40] ^= 1
			case "expired":
				time = timev4.Interval{LowerMS: 500, UpperMS: 501}
			}
			if _, err := codec.ParseRequest(data, key, time); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	// Expiry of the request's append deadline is preserved for terminal CAS.
	if _, err = codec.ParseRequest(wire, authority, timev4.Interval{LowerMS: 450, UpperMS: 451}); err != nil {
		t.Fatal(err)
	}
	response, facts := topUpResponseFixture(t, want, 1, 1, false, 0)
	batch, err := codec.ParseResponse(response, want)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := batch.Facts(); err != nil || got != facts {
		t.Fatal("response facts", err)
	}
	if _, err = codec.ParseRequest(wire, authority, now); err == nil {
		t.Fatal("retained batch did not pin parser")
	}
	material, err := batch.Material(0)
	if err != nil || !bytes.Equal(material, []byte{0xa1, 0, 0}) {
		t.Fatal("material", err)
	}
	batch.Release()
	if _, err = batch.Material(0); err == nil {
		t.Fatal("released material remained readable")
	}
	// Current generation 2 acknowledges an unchanged generation 1 response.
	ack := []Field{{Name: "operation_id", Kind: ByteString, Bytes: want.Operation[:]}, {Name: "pool_digest", Kind: ByteString, Bytes: want.Pool[:]}, {Name: "response_digest", Kind: ByteString, Bytes: facts.Digest[:]}, {Name: "server_highest_artifact_sequence", Number: facts.Highest}, {Name: "gap_authorized", Kind: Boolean}, {Name: "applied", Kind: Boolean, Number: 1}, {Name: "request_digest", Kind: ByteString, Bytes: want.Digest[:]}, {Name: "binding_generation", Number: 2}, {Name: "owner_fence_proof", Kind: ByteString, Bytes: proof}}
	if gen, err := codec.VerifyAck(topUpEncode(t, "TopUpAck", ack), want, facts, authority, now); err != nil || gen != 2 {
		t.Fatal("current owner Ack of old response", err)
	}
	ack[3].Number++
	if _, err := codec.VerifyAck(topUpEncode(t, "TopUpAck", ack), want, facts, authority, now); err == nil {
		t.Fatal("Ack changed original frontier")
	}
}

func TestTopUpRuntimeInstallationBounds(t *testing.T) {
	r, _, _ := topUpFixture(t)
	codec, _ := NewTopUpCodec()
	wire, facts := topUpResponseFixture(t, r, 1, 5, true, 4)
	batch, err := codec.ParseResponse(wire, r)
	if err != nil {
		t.Fatal(err)
	}
	batch.Release()
	if err := CheckTopUpInstallSequence(facts, 2); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TopUpResponseFacts){func(f *TopUpResponseFacts) { f.Gap = false }, func(f *TopUpResponseFacts) { f.RetiredThrough = 3 }, func(f *TopUpResponseFacts) { f.Highest++ }} {
		bad := facts
		mutate(&bad)
		if CheckTopUpInstallSequence(bad, 2) == nil {
			t.Fatal("unproven gap accepted")
		}
	}
	if CheckTopUpInstallSequence(facts, math.MaxUint64) == nil {
		t.Fatal("frontier wrapped")
	}
	r.MaxItemBytes = 3 // Three material bytes have a four-byte bstr encoding.
	if _, err = codec.ParseResponse(wire, r); err == nil {
		t.Fatal("encoded material bound ignored")
	}
	r.MaxItemBytes = 64
	r.Identity[0] ^= 1
	if _, err = codec.ParseResponse(wire, r); err == nil {
		t.Fatal("material identity changed")
	}
}

func TestTopUpRuntimeBuildersPreserveCanonicalIntentAndOriginalGeneration(t *testing.T) {
	request, requestWire, authority := topUpFixture(t)
	codec, err := NewTopUpCodec()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := codec.RequestDigest(request)
	if err != nil || digest != request.Digest {
		t.Fatal("intent before proof", err)
	}
	current := request
	current.Generation = 2
	if renewed, err := codec.RequestDigest(current); err != nil || renewed != digest {
		t.Fatal("generation entered intent digest", err)
	}
	dst := make([]byte, 524288)
	proof, _ := topUpProof(t, request, 1)
	n, err := codec.EncodeRequest(dst, request, proof)
	if err != nil || !bytes.Equal(dst[:n], requestWire) {
		t.Fatal("request encoding differs", err)
	}
	if _, err = codec.ParseRequest(dst[:n], authority, timev4.Interval{LowerMS: 200, UpperMS: 201}); err != nil {
		t.Fatal(err)
	}
	expected, facts := topUpResponseFixture(t, request, 1, 1, false, 0)
	items := []TopUpIssueEntry{{ExpiryMS: 1000, Material: []byte{0xa1, 0, 0}}, {ExpiryMS: 1000, Material: []byte{0xa1, 0, 1}}}
	n, err = codec.EncodeResponse(dst, request, 1, false, 0, items)
	if err != nil || !bytes.Equal(dst[:n], expected) {
		t.Fatal("response encoding differs", err)
	}
	batch, err := codec.ParseResponse(dst[:n], request)
	if err != nil {
		t.Fatal(err)
	}
	batch.Release()
	renewedProof, _ := topUpProof(t, request, 2)
	n, err = codec.EncodeAck(dst, request, facts, 2, renewedProof)
	if err != nil {
		t.Fatal(err)
	}
	if generation, err := codec.VerifyAck(dst[:n], request, facts, authority, timev4.Interval{LowerMS: 200, UpperMS: 201}); err != nil || generation != 2 {
		t.Fatal("history Ack builder", err)
	}
	replacement, _ := topUpResponseFixture(t, request, 2, 1, false, 0)
	if _, err = codec.ParseResponse(replacement, request); err == nil {
		t.Fatal("replacement generation changed original response")
	}
	request.MaxItemBytes = 3
	if _, err = codec.EncodeResponse(dst, request, 1, false, 0, items); err == nil {
		t.Fatal("encoded material size bypass")
	}
}
