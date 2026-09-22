package protocolv4

import (
	"bytes"
	"errors"
	"testing"
)

func TestCBORByteStringEnvelopeUsesOriginalMapEncoding(t *testing.T) {
	for _, size := range []int{0, 1, 23, 24, 255, 256, 8192} {
		payload := bytes.Repeat([]byte{0xdd}, size)
		fields := []Field{{Name: "offer", Kind: ByteString, Bytes: []byte{0xa0}}, {Name: "status", Number: 0}, {Name: "contract", Kind: ByteString}, {Name: "target_index", Number: 7}}
		var metadata [512]byte
		prefix, suffix, err := encodeMapByteStringEnvelope(metadata[:], "ContractSnapshot", fields, "contract", size)
		if err != nil {
			t.Fatal(size, err)
		}
		if len(metadata) < len(prefix)+len(suffix) {
			t.Fatal("unbounded envelope")
		}
		joined := append(bytes.Clone(prefix), payload...)
		joined = append(joined, suffix...)
		fields[2].Bytes = payload
		expected, err := EncodeMap(make([]byte, size+512), "ContractSnapshot", fields)
		if err != nil || !bytes.Equal(joined, expected) {
			t.Fatal("different canonical map", size, err)
		}
	}
	fields := []Field{{Name: "target_index", Number: 0}, {Name: "status", Number: 0}, {Name: "contract", Kind: ByteString}}
	for _, test := range []struct {
		name   string
		fields []Field
		target string
		length int
	}{
		{"missing target", fields, "absent", 1},
		{"wrong type", fields, "status", 1},
		{"negative length", fields, "contract", -1},
		{"duplicate field", append(append([]Field(nil), fields...), fields[2]), "contract", 1},
		{"missing required", fields[1:], "contract", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := encodeMapByteStringEnvelope(make([]byte, 512), "ContractSnapshot", test.fields, test.target, test.length); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}

// v4.go_contract_query.encoder_steps
func TestContractSnapshotWriterMaximumBoundedStepsAndOriginalBytes(t *testing.T) {
	f := newApplicationFixtures(t)
	original := queryRuntimeBytes(t, "contract_query_execution_maximum")
	parsed, _, err := f.r.decode(original, "ServiceContract", nil, 8192)
	appOK(t, err)
	targets := make([]ContractQueryTarget, 8)
	choices := make([]ContractSnapshotChoice, 8)
	items := []byte{0x88}
	for i := range choices {
		wire := f.change(t, "ServiceContract", parsed, "type_id", appUint(uint64(i+1))).encode(nil)
		if len(wire) != 8192 {
			t.Fatal(len(wire))
		}
		codec, err := NewServiceContractCodec(768)
		if err != nil {
			t.Fatal(err)
		}
		contract, err := codec.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		defer contract.Release()
		policy, err := contract.Policy()
		if err != nil {
			t.Fatal(err)
		}
		targets[i] = ContractQueryTarget{Namespace: policy.Namespace, Type: policy.Type}
		offer, err := EncodeMap(make([]byte, 256), "AdmissionOffer", []Field{{Name: "service_contract_digest", Kind: ByteString, Bytes: policy.Digest[:]}, {Name: "not_before_ms", Number: 0}, {Name: "not_after_ms", Number: 1}})
		if err != nil {
			t.Fatal(err)
		}
		choices[i] = ContractSnapshotChoice{Status: "available_full", Contract: contract, Offer: offer, MaxOfferWindowMS: 1}
		item, err := EncodeMap(make([]byte, 9000), "ContractSnapshot", []Field{{Name: "target_index", Number: uint64(i)}, {Name: "status", Number: 0}, {Name: "contract", Kind: ByteString, Bytes: wire}, {Name: "offer", Kind: ByteString, Bytes: offer}})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item...)
	}
	targetCodec, err := NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	_, request, err := targetCodec.EncodeTargets(make([]byte, 2048), targets, make([]*ServiceContract, 8))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := EncodeMap(make([]byte, 73728), "ContractSnapshots", []Field{{Name: "items", Kind: EncodedArray, Bytes: items}})
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := NewContractSnapshotEncoder()
	if err != nil {
		t.Fatal(err)
	}
	for _, width := range []int{1, 4096, 73728} {
		writer, err := encoder.NewWriter(request, choices)
		if err != nil {
			t.Fatal(err)
		}
		if writer.Size() != len(expected) {
			t.Fatal(writer.Size(), len(expected))
		}
		out := make([]byte, 73728)
		written := 0
		for steps := 0; ; steps++ {
			if steps > len(expected) {
				t.Fatal("no bounded progress")
			}
			n, done, err := writer.Next(out[written:min(written+width, len(out))])
			if err != nil || n > 4096 || n > width || n == 0 && !done {
				t.Fatal(n, done, err)
			}
			written += n
			if done {
				break
			}
		}
		if !bytes.Equal(out[:written], expected) {
			t.Fatal("bounded writer changed canonical bytes", width)
		}
		if n, done, err := writer.Next(nil); err != nil || n != 0 || !done {
			t.Fatal(n, done, err)
		}
		writer.Close()
		if _, _, err := writer.Next(out); !errors.Is(err, CBORFailure("encoder_closed")) {
			t.Fatal("closed writer resumed", err)
		}
	}
	writer, err := encoder.NewWriter(request, choices)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	scratch := make([]byte, 4096)
	if n, done, err := writer.Next(scratch); err != nil || n != 4096 || done {
		t.Fatal(n, done, err)
	}
	choices[0].Contract.Release()
	if _, done, err := writer.Next(scratch); !errors.Is(err, CBORFailure("document_released")) || done {
		t.Fatal("released source substituted", done, err)
	}
	if _, _, err := writer.Next(scratch); !errors.Is(err, CBORFailure("encoder_closed")) {
		t.Fatal("failed writer resumed", err)
	}
}
