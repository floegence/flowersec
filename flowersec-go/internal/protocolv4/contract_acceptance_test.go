package protocolv4

import (
	"testing"
	"unsafe"
)

func TestContractAcceptanceComparesEveryUnlistedCanonicalField(t *testing.T) {
	f := newApplicationFixtures(t)
	body := f.read(t, "ServiceContract", f.seeds["service_unary_execution"])
	p, err := BoundedContractAcceptance(ContractRange{Field: "history_retention_ms", Lower: 1, Upper: ^uint64(0)}, ContractRange{Field: "max_response_bytes", Lower: 1, Upper: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(value *cborRefValue) [32]byte {
		_, codec := applicationContractCodecs(t)
		c, err := codec.Decode(value.encode(nil))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Release()
		id, err := c.AcceptanceIdentity(p)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	original := identity(body)
	if got := identity(f.change(t, "ServiceContract", body, "history_retention_ms", appUint(123456))); got != original {
		t.Fatal("allowed retention changed fixed identity")
	}
	if got := identity(f.change(t, "ServiceContract", body, "request_max_bytes", appUint(777))); got == original {
		t.Fatal("unlisted request bound ignored")
	}
	if got := identity(f.change(t, "ServiceContract", body, "response_schema_revision", &cborRefValue{major: 3, data: []byte("schema.other")})); got == original {
		t.Fatal("schema change ignored")
	}
	if got := identity(f.change(t, "ServiceContract", body, "execution_mode", appUint(0))); got == original {
		t.Fatal("durability change ignored")
	}
}

func TestContractAcceptanceClosedVariantAndRangeSchema(t *testing.T) {
	if unsafe.Sizeof(ContractAcceptance{}) > 256 {
		t.Fatal("acceptance exceeded per-method budget")
	}
	for _, ranges := range [][]ContractRange{
		nil,
		{{Field: "unknown", Lower: 0, Upper: 1}},
		{{Field: "history_retention_ms", Lower: 0, Upper: 1}},
		{{Field: "max_response_bytes", Lower: 2, Upper: 1}},
		{{Field: "max_response_bytes", Lower: 1, Upper: 1048577}},
		{{Field: "max_response_bytes", Lower: 1, Upper: 4}, {Field: "max_response_bytes", Lower: 2, Upper: 8}},
	} {
		if _, err := BoundedContractAcceptance(ranges...); err != ErrContractPolicyRejected {
			t.Fatal(ranges, err)
		}
	}
	f := newApplicationFixtures(t)
	for _, test := range []struct {
		body, field  string
		lower, upper uint64
	}{
		{"service_unary_transient", "history_retention_ms", 1, 999999},
		{"service_unary_execution", "result_retention_ms", 1, 1},
		{"service_notify_observation", "max_response_bytes", 0, 1048576},
	} {
		t.Run(test.body+"/"+test.field, func(t *testing.T) {
			_, codec := applicationContractCodecs(t)
			c, err := codec.Decode(f.seeds[test.body])
			if err != nil {
				t.Fatal(err)
			}
			defer c.Release()
			policy, _ := BoundedContractAcceptance(ContractRange{Field: test.field, Lower: test.lower, Upper: test.upper})
			if _, err := c.AcceptanceIdentity(policy); err != ErrContractPolicyRejected {
				t.Fatal("inapplicable or out-of-range policy accepted", err)
			}
		})
	}
}
