package protocolv4

// Independent test-only integer arithmetic; no clock, source, owner or timer.
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

type timeSpec struct {
	Operations  map[string][]string `json:"operations"`
	Maximum     string              `json:"quantity_max"`
	WideMaximum string              `json:"intermediate_max"`
}

func timeRegistry(t testing.TB) timeSpec {
	t.Helper()
	var spec timeSpec
	if err := json.Unmarshal([]byte(TimeArithmeticRegistryJSON), &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

func timeCompute(spec timeSpec, operation string, input any) (map[string]string, error) {
	fields, ok := spec.Operations[operation]
	if !ok {
		return nil, fmt.Errorf("time_operation")
	}
	object, ok := input.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("time_input_object")
	}
	if len(object) != len(fields) {
		return nil, fmt.Errorf("time_input_fields")
	}
	for key := range object {
		if !slices.Contains(fields, key) {
			return nil, fmt.Errorf("time_input_fields")
		}
	}
	maximum, _ := new(big.Int).SetString(spec.Maximum, 10)
	wideMaximum, _ := new(big.Int).SetString(spec.WideMaximum, 10)
	values := map[string]*big.Int{}
	for _, key := range fields {
		text, ok := object[key].(string)
		if !ok || len(text) == 0 || len(text) > len(spec.Maximum) || len(text) > 1 && text[0] == '0' {
			return nil, fmt.Errorf("time_integer")
		}
		for _, c := range text {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("time_integer")
			}
		}
		n, ok := new(big.Int).SetString(text, 10)
		if !ok || n.Cmp(maximum) > 0 {
			return nil, fmt.Errorf("time_integer")
		}
		values[key] = n
	}
	add := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Sub(a, b) }
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mul(a, b) }
	div := func(a, b *big.Int) *big.Int { return new(big.Int).Quo(a, b) }
	ceil := func(a, b *big.Int) *big.Int {
		q, rem := new(big.Int), new(big.Int)
		q.QuoRem(a, b, rem)
		if rem.Sign() != 0 {
			q.Add(q, big.NewInt(1))
		}
		return q
	}
	bounded := func(n *big.Int) bool { return n.Sign() >= 0 && n.Cmp(maximum) <= 0 }
	n, d, q := values["rate_numerator"], values["rate_denominator"], values["quantization_ms"]
	if d.Sign() == 0 || n.Cmp(d) >= 0 {
		return nil, fmt.Errorf("time_rate")
	}
	elapsed := func() (*big.Int, *big.Int, error) {
		low := sub(values["delta_ms"], q)
		if low.Sign() < 0 {
			low.SetInt64(0)
		}
		high := add(values["delta_ms"], q)
		if !bounded(high) {
			return nil, nil, fmt.Errorf("time_overflow")
		}
		lowerProduct, upperProduct := mul(low, d), mul(high, d)
		if lowerProduct.Cmp(wideMaximum) > 0 || upperProduct.Cmp(wideMaximum) > 0 {
			return nil, nil, fmt.Errorf("time_overflow")
		}
		lo := div(lowerProduct, add(d, n))
		hi := ceil(upperProduct, sub(d, n))
		if !bounded(hi) {
			return nil, nil, fmt.Errorf("time_overflow")
		}
		return lo, hi, nil
	}
	interval := func(lo, hi *big.Int) (map[string]string, error) {
		if !bounded(lo) || !bounded(hi) {
			return nil, fmt.Errorf("time_overflow")
		}
		if lo.Cmp(hi) > 0 {
			return nil, fmt.Errorf("time_interval")
		}
		if values["max_width_ms"].Sign() == 0 || sub(hi, lo).Cmp(values["max_width_ms"]) > 0 {
			return nil, fmt.Errorf("time_width")
		}
		return map[string]string{"lower_ms": lo.String(), "upper_ms": hi.String()}, nil
	}
	switch operation {
	case "elapsed":
		lo, hi, err := elapsed()
		if err != nil {
			return nil, err
		}
		return map[string]string{"elapsed_lower_ms": lo.String(), "elapsed_upper_ms": hi.String()}, nil
	case "network_anchor":
		_, hi, err := elapsed()
		if err != nil {
			return nil, err
		}
		if values["max_round_trip_ms"].Sign() == 0 || hi.Cmp(values["max_round_trip_ms"]) > 0 {
			return nil, fmt.Errorf("time_round_trip")
		}
		return interval(sub(values["sample_ms"], values["source_error_ms"]), add(add(values["sample_ms"], values["source_error_ms"]), hi))
	case "advance_anchor":
		if values["lower_ms"].Cmp(values["upper_ms"]) > 0 {
			return nil, fmt.Errorf("time_interval")
		}
		lo, hi, err := elapsed()
		if err != nil {
			return nil, err
		}
		if values["max_age_ms"].Sign() == 0 || hi.Cmp(values["max_age_ms"]) > 0 {
			return nil, fmt.Errorf("time_anchor_age")
		}
		return interval(add(values["lower_ms"], lo), add(values["upper_ms"], hi))
	case "deadline_delta":
		slack := sub(values["deadline_ms"], values["upper_ms"])
		if slack.Sign() <= 0 {
			return nil, fmt.Errorf("time_expired")
		}
		product := mul(slack, sub(d, n))
		if product.Cmp(wideMaximum) > 0 {
			return nil, fmt.Errorf("time_overflow")
		}
		budget := div(product, d)
		if budget.Cmp(q) < 0 {
			return nil, fmt.Errorf("time_deadline_unrepresentable")
		}
		return map[string]string{"delta_ms": sub(budget, q).String()}, nil
	case "prove_delta":
		gap := sub(values["bound_ms"], values["lower_ms"])
		if gap.Sign() <= 0 {
			return map[string]string{"delta_ms": "0"}, nil
		}
		product := mul(gap, add(d, n))
		if product.Cmp(wideMaximum) > 0 {
			return nil, fmt.Errorf("time_overflow")
		}
		result := add(ceil(product, d), q)
		if !bounded(result) {
			return nil, fmt.Errorf("time_overflow")
		}
		return map[string]string{"delta_ms": result.String()}, nil
	}
	return nil, fmt.Errorf("time_operation")
}

func TestV4TimeCorpus(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/transport_v4/time_arithmetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID        string            `json:"id"`
			Operation string            `json:"operation"`
			Input     map[string]any    `json:"input"`
			Expected  map[string]string `json:"expected"`
			Error     string            `json:"expected_error"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != 37 {
		t.Fatal("incomplete corpus")
	}
	spec := timeRegistry(t)
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			before, _ := json.Marshal(v.Input)
			actual, err := timeCompute(spec, v.Operation, v.Input)
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

func TestV4TimeRoundingAndInverse(t *testing.T) {
	spec := timeRegistry(t)
	for d := int64(1); d <= 8; d++ {
		for n := int64(0); n < d; n++ {
			for gap := int64(1); gap <= 20; gap++ {
				for q := int64(0); q <= 2; q++ {
					run := func(op string, fields map[string]int64, result string) int64 {
						input := map[string]any{"rate_numerator": strconv.FormatInt(n, 10), "rate_denominator": strconv.FormatInt(d, 10), "quantization_ms": strconv.FormatInt(q, 10)}
						for k, v := range fields {
							input[k] = strconv.FormatInt(v, 10)
						}
						out, err := timeCompute(spec, op, input)
						if err != nil {
							t.Fatal(err)
						}
						value, err := strconv.ParseInt(out[result], 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						return value
					}
					elapsed := func(delta int64, result string) int64 {
						return run("elapsed", map[string]int64{"delta_ms": delta}, result)
					}
					lo, hi := elapsed(gap, "elapsed_lower_ms"), elapsed(gap, "elapsed_upper_ms")
					if lo*(d+n) > max(0, gap-q)*d || hi*(d-n) < (gap+q)*d {
						t.Fatal("inward rounding")
					}
					if q <= gap*(d-n)/d {
						delta := run("deadline_delta", map[string]int64{"upper_ms": 0, "deadline_ms": gap}, "delta_ms")
						if elapsed(delta, "elapsed_upper_ms") > gap || elapsed(delta+1, "elapsed_upper_ms") <= gap {
							t.Fatal("deadline not maximal")
						}
					}
					delta := run("prove_delta", map[string]int64{"lower_ms": 0, "bound_ms": gap}, "delta_ms")
					if elapsed(delta, "elapsed_lower_ms") < gap || elapsed(delta-1, "elapsed_lower_ms") >= gap {
						t.Fatal("proving increment not minimal")
					}
				}
			}
		}
	}
}

func TestV4TimeInputBoundary(t *testing.T) {
	spec := timeRegistry(t)
	for _, bad := range []any{1, true, nil, "", "01", "-1", "+1", "1.0", "1\n", "١", "18446744073709551616"} {
		_, err := timeCompute(spec, "elapsed", map[string]any{"rate_numerator": "0", "rate_denominator": "1", "quantization_ms": "0", "delta_ms": bad})
		if err == nil || err.Error() != "time_integer" {
			t.Fatalf("accepted %v: %v", bad, err)
		}
	}
	for _, input := range []any{nil, []any{}, map[string]any{}} {
		if _, err := timeCompute(spec, "elapsed", input); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	if _, err := timeCompute(spec, "unknown", nil); err == nil || err.Error() != "time_operation" {
		t.Fatal(err)
	}
}
