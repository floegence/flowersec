package protocolv4

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"
)

type queryRuntimeVector struct {
	ID, Schema, Hex string
	ExpectedError   string `json:"expected_error"`
}

func queryRuntimeCorpus(t *testing.T) []queryRuntimeVector {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []queryRuntimeVector }
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Vectors
}
func queryRuntimeBytes(t *testing.T, id string) []byte {
	t.Helper()
	for _, v := range queryRuntimeCorpus(t) {
		if v.ID == id {
			raw, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
	}
	t.Fatal("missing vector", id)
	return nil
}

// v4.go_contract_query.targets
func TestContractQueryRuntimeTargetsSharedCorpus(t *testing.T) {
	c, err := NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, v := range queryRuntimeCorpus(t) {
		if v.Schema != "ContractTargets" {
			continue
		}
		count++
		t.Run(v.ID, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			q, err := c.DecodeTargets(wire)
			if v.ExpectedError != "" {
				if err == nil {
					t.Fatal("accepted invalid request")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if q.Count() < 1 || q.Count() > 8 || q.ResponseBytes() != uint32(q.Count())*9216 {
				t.Fatal(q.Count(), q.ResponseBytes())
			}
			before, _ := q.Target(0)
			clear(wire)
			if _, err = c.DecodeTargets(queryRuntimeBytes(t, "contract_targets_plain")); err != nil {
				t.Fatal(err)
			}
			after, _ := q.Target(0)
			if before != after {
				t.Fatal("projection retained reusable decoder input")
			}
		})
	}
	if count < 25 {
		t.Fatal("incomplete target corpus", count)
	}
}

func TestContractQueryRuntimeKnownBodiesAndEncoding(t *testing.T) {
	c, err := NewContractQueryCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"unary_transient", "unary_execution", "stream_transient", "stream_execution", "notify_observation", "notify_execution"} {
		t.Run(variant, func(t *testing.T) {
			contractCodec, err := NewServiceContractCodec(2048)
			if err != nil {
				t.Fatal(err)
			}
			contract, err := contractCodec.Decode(queryRuntimeBytes(t, "service_"+variant))
			if err != nil {
				t.Fatal(err)
			}
			defer contract.Release()
			for _, mode := range []string{"known", "wanted", "both"} {
				wire := queryRuntimeBytes(t, "contract_targets_"+mode+"_"+variant)
				request, err := c.DecodeTargets(wire)
				if err != nil {
					t.Fatal(err)
				}
				target, err := request.Target(0)
				if err != nil {
					t.Fatal(err)
				}
				known := []*ServiceContract{nil}
				if target.HasKnown {
					known[0] = contract
				}
				if err = request.CheckKnown(known); err != nil {
					t.Fatal(err)
				}
				var encoded [2048]byte
				count, again, err := c.EncodeTargets(encoded[:], []ContractQueryTarget{target}, known)
				if err != nil || !bytes.Equal(encoded[:count], wire) || again != request {
					t.Fatal("canonical target mismatch", err)
				}
				if target.HasKnown {
					if err = request.CheckKnown([]*ServiceContract{nil}); err == nil {
						t.Fatal("bare digest stood for known body")
					}
				} else if err = request.CheckKnown([]*ServiceContract{contract}); err == nil {
					t.Fatal("unrequested body accepted")
				}
			}
			request, err := c.DecodeTargets(queryRuntimeBytes(t, "contract_targets_known_"+variant))
			if err != nil {
				t.Fatal(err)
			}
			contract.Release()
			if err = request.CheckKnown([]*ServiceContract{contract}); !errors.Is(err, CBORFailure("document_released")) {
				t.Fatal("released body remained known", err)
			}
		})
	}
	if _, _, err = c.EncodeTargets(make([]byte, 2048), []ContractQueryTarget{{Namespace: "acme/files", Type: 1}, {Namespace: "acme/files", Type: 1}}, []*ServiceContract{nil, nil}); err == nil {
		t.Fatal("duplicate targets encoded")
	}
}

// v4.go_contract_query.offers
func TestAdmissionOfferRuntimeExactContractVariantAndWindow(t *testing.T) {
	d, err := NewAdmissionOfferDecoder()
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"unary_transient", "unary_execution", "stream_transient", "stream_execution", "notify_observation", "notify_execution"} {
		t.Run(variant, func(t *testing.T) {
			c, err := NewServiceContractCodec(2048)
			if err != nil {
				t.Fatal(err)
			}
			contract, err := c.Decode(queryRuntimeBytes(t, "service_"+variant))
			if err != nil {
				t.Fatal(err)
			}
			defer contract.Release()
			policy, err := contract.Policy()
			if err != nil {
				t.Fatal(err)
			}
			makeOffer := func(hash [32]byte, start, end uint64) []byte {
				var buffer [256]byte
				wire, err := EncodeMap(buffer[:], "AdmissionOffer", []Field{{Name: "service_contract_digest", Kind: ByteString, Bytes: hash[:]}, {Name: "not_before_ms", Number: start}, {Name: "not_after_ms", Number: end}})
				if err != nil {
					t.Fatal(err)
				}
				return bytes.Clone(wire)
			}
			wire := makeOffer(policy.Digest, 0, 60000)
			got, err := contract.CheckOffer(d, wire, 60000)
			if policy.Semantics != 1 {
				if err == nil {
					t.Fatal("nonexecution acquired an Offer")
				}
				return
			}
			if err != nil || got.Digest != policy.Digest || got.NotBeforeMS != 0 || got.NotAfterMS != 60000 {
				t.Fatal(got, err)
			}
			for _, bad := range []struct{ start, end, limit uint64 }{{0, 60000, 59999}, {60000, 60000, 60000}, {60001, 60000, math.MaxUint64}, {0, 1, 0}} {
				if _, err = contract.CheckOffer(d, makeOffer(policy.Digest, bad.start, bad.end), bad.limit); err == nil {
					t.Fatal("invalid window accepted", bad)
				}
			}
			if got, err = contract.CheckOffer(d, makeOffer(policy.Digest, math.MaxUint64-1, math.MaxUint64), 1); err != nil || got.NotAfterMS != math.MaxUint64 {
				t.Fatal(got, err)
			}
			wrong := policy.Digest
			wrong[0] ^= 1
			if _, err = contract.CheckOffer(d, makeOffer(wrong, 0, 1), 1); !errors.Is(err, CBORFailure("offer_contract_mismatch")) {
				t.Fatal("foreign Offer accepted", err)
			}
		})
	}
}
