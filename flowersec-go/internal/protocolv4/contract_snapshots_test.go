package protocolv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

// v4.go_contract_query.snapshots
func TestContractSnapshotsRuntimeSharedQueryCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/queries.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID     string
			Inputs struct {
				Request  string    `json:"request_hex"`
				Response string    `json:"response_hex"`
				Known    []*string `json:"known_contracts_hex"`
				Windows  []*string `json:"offer_window_limits"`
			}
			Result        json.RawMessage
			ExpectedError string `json:"expected_error"`
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	targets, err := NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			decode := func(s string) []byte {
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			request, err := targets.DecodeTargets(decode(v.Inputs.Request))
			if err != nil {
				t.Fatal(err)
			}
			known := make([]*ServiceContract, len(v.Inputs.Known))
			for i, body := range v.Inputs.Known {
				if body == nil {
					continue
				}
				codec, err := NewServiceContractCodec(768)
				if err != nil {
					t.Fatal(err)
				}
				known[i], err = codec.Decode(decode(*body))
				if err != nil {
					t.Fatal(err)
				}
				defer known[i].Release()
			}
			if v.Inputs.Response == "" {
				if err := request.CheckKnown(known); err != nil {
					t.Fatal(err)
				}
				return
			}
			windows := make([]uint64, len(v.Inputs.Windows))
			for i, value := range v.Inputs.Windows {
				if value != nil {
					windows[i], err = strconv.ParseUint(*value, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			output := make([][]byte, request.Count())
			for i := range output {
				output[i] = bytes.Repeat([]byte{0xee}, 8192)
			}
			result, err := decodeSnapshotsBoth(t, snapshots, request, decode(v.Inputs.Response), known, windows, output)
			if v.ExpectedError != "" {
				if !errors.Is(err, CBORFailure(v.ExpectedError)) {
					t.Fatal("unexpected error", v.ExpectedError, err)
				}
				for _, body := range output {
					if !bytes.Equal(body, bytes.Repeat([]byte{0xee}, 8192)) {
						t.Fatal("invalid response partially published a body")
					}
				}
				return
			}
			var expectedItems []struct {
				Status string
				Digest string `json:"contract_digest_hex"`
				Offer  *struct {
					Start uint64 `json:"not_before_ms,string"`
					End   uint64 `json:"not_after_ms,string"`
				}
			}
			if err := json.Unmarshal(v.Result, &expectedItems); err != nil {
				t.Fatal(err)
			}
			if err != nil || result.Count() != len(expectedItems) {
				t.Fatal(result, err)
			}
			choices := make([]ContractSnapshotChoice, result.Count())
			for i, expected := range expectedItems {
				info, err := result.Item(i)
				if err != nil || info.Status != expected.Status {
					t.Fatal(info, err)
				}
				if expected.Digest != "" && hex.EncodeToString(info.Policy.Digest[:]) != expected.Digest {
					t.Fatal("wrong exact contract digest")
				}
				if (expected.Offer != nil) != info.HasOffer {
					t.Fatal("Offer presence")
				}
				if expected.Offer != nil && (info.Offer.NotBeforeMS != expected.Offer.Start || info.Offer.NotAfterMS != expected.Offer.End) {
					t.Fatal(info.Offer)
				}
				choices[i].Status = info.Status
				if info.HasOffer {
					offer, err := EncodeMap(make([]byte, 256), "AdmissionOffer", []Field{{Name: "service_contract_digest", Kind: ByteString, Bytes: info.Offer.Digest[:]}, {Name: "not_before_ms", Number: info.Offer.NotBeforeMS}, {Name: "not_after_ms", Number: info.Offer.NotAfterMS}})
					if err != nil {
						t.Fatal(err)
					}
					choices[i].Offer, choices[i].MaxOfferWindowMS = offer, windows[i]
				}
				if info.Status == "available_unchanged" {
					choices[i].Contract = known[i]
				}
				if info.Status == "available_full" {
					codec, err := NewServiceContractCodec(768)
					if err != nil {
						t.Fatal(err)
					}
					contract, err := codec.Decode(output[i][:info.ContractBytes])
					if err != nil {
						t.Fatal(err)
					}
					digest, err := contract.Digest()
					choices[i].Contract = contract
					defer contract.Release()
					if err != nil || digest != info.Policy.Digest {
						t.Fatal("copied body differs", err)
					}
				} else if !bytes.Equal(output[i], bytes.Repeat([]byte{0xee}, 8192)) {
					t.Fatal("non-full status wrote a replacement body")
				}
			}
			encoded := make([]byte, request.ResponseBytes())
			length, err := snapshots.Encode(encoded, request, choices)
			if err != nil || !bytes.Equal(encoded[:length], decode(v.Inputs.Response)) {
				t.Fatal("response encoder differs from shared corpus", err)
			}
		})
	}
}

// v4.go_contract_query.bounded_workspace
func TestContractSnapshotsRuntimeMaximumAndNoPartialOutput(t *testing.T) {
	f := newApplicationFixtures(t)
	contractWire := queryRuntimeBytes(t, "contract_query_execution_maximum")
	parsed, _, err := f.r.decode(contractWire, "ServiceContract", nil, 8192)
	appOK(t, err)
	var contracts [8][]byte
	var targets []ContractQueryTarget
	var items []byte
	items = append(items, 0x88)
	for i := range contracts {
		changed := f.change(t, "ServiceContract", parsed, "type_id", appUint(uint64(i+1)))
		contracts[i] = changed.encode(nil)
		if len(contracts[i]) != 8192 {
			t.Fatal("maximum contract encoding changed", len(contracts[i]))
		}
		codec, err := NewServiceContractCodec(768)
		if err != nil {
			t.Fatal(err)
		}
		contract, err := codec.Decode(contracts[i])
		if err != nil {
			t.Fatal(err)
		}
		policy, err := contract.Policy()
		if err != nil {
			t.Fatal(err)
		}
		contract.Release()
		targets = append(targets, ContractQueryTarget{Namespace: policy.Namespace, Type: policy.Type})
		var offer [256]byte
		offerWire, err := EncodeMap(offer[:], "AdmissionOffer", []Field{{Name: "service_contract_digest", Kind: ByteString, Bytes: policy.Digest[:]}, {Name: "not_before_ms", Number: 0}, {Name: "not_after_ms", Number: 1}})
		if err != nil {
			t.Fatal(err)
		}
		var encoded [9000]byte
		item, err := EncodeMap(encoded[:], "ContractSnapshot", []Field{{Name: "target_index", Number: uint64(i)}, {Name: "status", Number: 0}, {Name: "contract", Kind: ByteString, Bytes: contracts[i]}, {Name: "offer", Kind: ByteString, Bytes: offerWire}})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item...)
	}
	codec, err := NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	var requestWire [2048]byte
	_, request, err := codec.EncodeTargets(requestWire[:], targets, make([]*ServiceContract, 8))
	if err != nil {
		t.Fatal(err)
	}
	response, err := EncodeMap(make([]byte, 73728), "ContractSnapshots", []Field{{Name: "items", Kind: EncodedArray, Bytes: items}})
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	output := make([][]byte, 8)
	for i := range output {
		output[i] = bytes.Repeat([]byte{0xcc}, 8192)
	}
	windows := []uint64{1, 1, 1, 1, 1, 1, 1, 1}
	// The last local target capacity fails after seven complete validations.
	output[7] = output[7][:1]
	if _, err = decodeSnapshotsBoth(t, snapshots, request, response, make([]*ServiceContract, 8), windows, output); !errors.Is(err, CBORFailure("encoder_capacity")) {
		t.Fatal(err)
	}
	for _, dst := range output {
		if !bytes.Equal(dst, bytes.Repeat([]byte{0xcc}, len(dst))) {
			t.Fatal("earlier body escaped failing aggregate gate")
		}
	}
	output[7] = output[7][:8192]
	result, err := decodeSnapshotsBoth(t, snapshots, request, response, make([]*ServiceContract, 8), windows, output)
	if err != nil || result.Count() != 8 {
		t.Fatal(result, err)
	}
	for i := range output {
		info, _ := result.Item(i)
		if !bytes.Equal(output[i][:info.ContractBytes], contracts[i]) {
			t.Fatal("maximum body changed", i)
		}
	}
	output[1] = output[0]
	if _, err = decodeSnapshotsBoth(t, snapshots, request, response, make([]*ServiceContract, 8), windows, output); !errors.Is(err, CBORFailure("query_output_alias")) {
		t.Fatal("overlapping destinations", err)
	}
	if _, err = snapshots.envelope.DecodeMap(contractWire, "ServiceContract", DecodeContext{}); !errors.Is(err, CBORFailure("configuration_capacity")) {
		t.Fatal("envelope became a weaker contract decoder", err)
	}
}

func TestContractSnapshotsRuntimeRejectsMalformedNestedBodyBeforeDelivery(t *testing.T) {
	targets, err := NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	request, err := targets.DecodeTargets(queryRuntimeBytes(t, "contract_targets_plain"))
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := NewContractSnapshotCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{{0xa0}, {0xa2, 0, 1, 0, 2}, {0xbf, 0xff}} {
		var encoded [128]byte
		entry, err := EncodeMap(encoded[:], "ContractSnapshot", []Field{{Name: "target_index", Number: 0}, {Name: "status", Number: 0}, {Name: "contract", Kind: ByteString, Bytes: body}})
		if err != nil {
			t.Fatal(err)
		}
		array := append([]byte{0x81}, entry...)
		response, err := EncodeMap(make([]byte, 256), "ContractSnapshots", []Field{{Name: "items", Kind: EncodedArray, Bytes: array}})
		if err != nil {
			t.Fatal(err)
		}
		output := bytes.Repeat([]byte{0xfe}, 8192)
		if _, err = decodeSnapshotsBoth(t, snapshots, request, response, []*ServiceContract{nil}, []uint64{0}, [][]byte{output}); err == nil {
			t.Fatal("outer envelope bypassed complete contract validation")
		}
		if !bytes.Equal(output, bytes.Repeat([]byte{0xfe}, 8192)) {
			t.Fatal("malformed nested body escaped")
		}
	}
}
