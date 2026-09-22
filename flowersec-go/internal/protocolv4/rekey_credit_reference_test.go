package protocolv4

// Independent test arithmetic; no live owner, INIT/ACK gate or reservation.
import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

func rekeyCreditCompute(t testing.TB, profile, operation string, input any) (map[string]any, error) {
	t.Helper()
	var spec struct {
		Operations map[string][]string `json:"operations"`
		Maximum    string              `json:"quantity_max"`
		Wide       string              `json:"intermediate_max"`
		Bounds     map[string]string   `json:"elapsed_bound"`
		Fields     map[string]struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Min  uint64 `json:"min"`
		} `json:"envelope_fields"`
	}
	var usage struct {
		Profiles map[string]struct {
			Epochs string `json:"max_epochs"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(RekeyCreditRegistryJSON), &spec); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(CryptoUsageRegistryJSON), &usage); err != nil {
		t.Fatal(err)
	}
	usageProfile, ok := usage.Profiles[profile]
	if !ok {
		return nil, fmt.Errorf("rekey_credit_profile")
	}
	fields, ok := spec.Operations[operation]
	if !ok {
		return nil, fmt.Errorf("rekey_credit_operation")
	}
	object, ok := input.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rekey_credit_input")
	}
	if len(object) != len(fields) {
		return nil, fmt.Errorf("rekey_credit_fields")
	}
	for k := range object {
		if !slices.Contains(fields, k) {
			return nil, fmt.Errorf("rekey_credit_fields")
		}
	}
	values := map[string]*big.Int{}
	maximum, _ := new(big.Int).SetString(spec.Maximum, 10)
	wideMaximum, _ := new(big.Int).SetString(spec.Wide, 10)
	for _, key := range fields {
		s, ok := object[key].(string)
		if !ok || len(s) == 0 || len(s) > len(spec.Maximum) || len(s) > 1 && s[0] == '0' {
			return nil, fmt.Errorf("rekey_credit_integer")
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("rekey_credit_integer")
			}
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.Cmp(maximum) > 0 {
			return nil, fmt.Errorf("rekey_credit_integer")
		}
		values[key] = n
	}
	capacityError := fmt.Errorf("configuration_capacity")
	for _, f := range spec.Fields {
		if v, ok := values[f.Name]; ok {
			bits, err := strconv.Atoi(f.Type[4:])
			if err != nil {
				t.Fatal(err)
			}
			if v.Cmp(new(big.Int).SetUint64(f.Min)) < 0 || v.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(bits))) >= 0 {
				return nil, capacityError
			}
		}
	}
	add := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }
	div := func(a, b *big.Int) *big.Int { return new(big.Int).Quo(a, b) }
	overflow := false
	mul := func(a, b *big.Int) *big.Int {
		n := new(big.Int).Mul(a, b)
		if n.Sign() < 0 || n.Cmp(wideMaximum) > 0 {
			overflow = true
		}
		return n
	}
	ceil := func(a, b *big.Int) *big.Int {
		q, r := new(big.Int), new(big.Int)
		q.QuoRem(a, b, r)
		if r.Sign() != 0 {
			q.Add(q, big.NewInt(1))
		}
		return q
	}
	B, R := values["burst_rounds"], values["refill_period_ms"]
	C := mul(B, R)
	E, _ := new(big.Int).SetString(usageProfile.Epochs, 10)
	if B.Cmp(E) >= 0 {
		return nil, capacityError
	}
	if operation == "service" {
		n, d, q := values["rate_numerator"], values["rate_denominator"], values["quantization_ms"]
		if d.Sign() == 0 || n.Cmp(d) >= 0 || values["issued_at_ms"].Cmp(values["session_not_after_ms"]) >= 0 {
			return nil, capacityError
		}
		dm, dp, T := sub(d, n), add(d, n), sub(values["session_not_after_ms"], values["issued_at_ms"])
		maxError := div(sub(R, big.NewInt(1)), B)
		if maxError.Sign() == 0 || q.Cmp(div(mul(sub(maxError, big.NewInt(1)), dm), mul(big.NewInt(2), d))) > 0 {
			return nil, capacityError
		}
		e := add(ceil(mul(mul(big.NewInt(2), q), d), dm), big.NewInt(1))
		period := sub(R, mul(B, e))
		if period.Sign() <= 0 {
			return nil, capacityError
		}
		denominator, initial, rate := mul(period, dm), mul(C, dm), mul(B, dp)
		limit := mul(E, denominator)
		if initial.Cmp(limit) >= 0 || T.Cmp(div(sub(sub(limit, big.NewInt(1)), initial), rate)) > 0 {
			return nil, capacityError
		}
		numerator := add(initial, mul(rate, T))
		rounds := div(numerator, denominator)
		if overflow || numerator.Cmp(wideMaximum) > 0 || rounds.Sign() <= 0 || rounds.Cmp(E) >= 0 {
			return nil, capacityError
		}
		return map[string]any{"service_ms": T.String(), "error_allowance_ms": e.String(), "denominator_ms": period.String(), "capacity_credit": C.String(), "max_rounds": rounds.String(), "required_epochs": add(rounds, big.NewInt(1)).String()}, nil
	}
	available := C
	if operation != "initial_credit" {
		base := values["base_credit"]
		if base.Cmp(C) > 0 {
			return nil, capacityError
		}
		timeInput := map[string]any{}
		for _, key := range []string{"delta_ms", "rate_numerator", "rate_denominator", "quantization_ms"} {
			timeInput[key] = values[key].String()
		}
		elapsed, err := timeCompute(timeRegistry(t), "elapsed", timeInput)
		if err != nil {
			return nil, err
		}
		u, _ := new(big.Int).SetString(elapsed[spec.Bounds[operation]], 10)
		if u.Cmp(R) < 0 {
			refill := mul(B, u)
			if refill.Cmp(sub(C, base)) < 0 {
				available = add(base, refill)
			}
		}
	}
	if overflow {
		return nil, capacityError
	}
	var post any
	if available.Cmp(R) >= 0 {
		post = sub(available, R).String()
	}
	return map[string]any{"capacity_credit": C.String(), "available_credit": available.String(), "post_charge_credit": post}, nil
}

func TestV4RekeyCreditCorpus(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/transport_v4/rekey_credit.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID        string         `json:"id"`
			Profile   string         `json:"profile"`
			Operation string         `json:"operation"`
			Input     map[string]any `json:"input"`
			Expected  map[string]any `json:"expected"`
			Error     string         `json:"expected_error"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != 48 {
		t.Fatal("incomplete corpus")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			before, _ := json.Marshal(v.Input)
			actual, err := rekeyCreditCompute(t, v.Profile, v.Operation, v.Input)
			if v.Error != "" {
				if err == nil || err.Error() != v.Error {
					t.Fatalf("got %v; want %s", err, v.Error)
				}
			} else if err != nil || !reflect.DeepEqual(actual, v.Expected) {
				t.Fatalf("got %v %v; want %v", actual, err, v.Expected)
			}
			after, _ := json.Marshal(v.Input)
			if string(before) != string(after) {
				t.Fatal("input changed")
			}
		})
	}
}

func TestV4RekeyCreditBoundariesAndInputs(t *testing.T) {
	for duration := uint64(1); duration <= 120; duration++ {
		input := map[string]any{"burst_rounds": "2", "refill_period_ms": "30", "request_start_budget_ms": "5", "issued_at_ms": "0", "session_not_after_ms": strconv.FormatUint(duration, 10), "rate_numerator": "1", "rate_denominator": "2", "quantization_ms": "2"}
		out, err := rekeyCreditCompute(t, DHProfileX25519, "service", input)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := strconv.ParseUint(out["max_rounds"].(string), 10, 64)
		if n*12 > 60+6*duration || (n+1)*12 <= 60+6*duration {
			t.Fatal("incorrect service floor")
		}
	}
	for _, bad := range []any{1, uint64(1), true, nil, "", "01", "-1", "+1", "1.0", "1\n", "١", "18446744073709551616"} {
		_, err := rekeyCreditCompute(t, DHProfileX25519, "initial_credit", map[string]any{"burst_rounds": bad, "refill_period_ms": "30"})
		if err == nil || err.Error() != "rekey_credit_integer" {
			t.Fatalf("incorrect input rejection: %v", err)
		}
	}
	input := map[string]any{"burst_rounds": "2", "refill_period_ms": "30", "base_credit": "10", "delta_ms": "9", "rate_numerator": "0", "rate_denominator": "1", "quantization_ms": "0"}
	for i := 0; i < 50; i++ {
		out, err := rekeyCreditCompute(t, DHProfileX25519, "client_credit", input)
		if err != nil || out["available_credit"] != "28" || out["post_charge_credit"] != nil {
			t.Fatalf("peek changed: %v %v", out, err)
		}
	}
	input["delta_ms"] = "10"
	out, err := rekeyCreditCompute(t, DHProfileX25519, "client_credit", input)
	if err != nil || out["post_charge_credit"] != "0" {
		t.Fatal("lost partial balance")
	}
}
