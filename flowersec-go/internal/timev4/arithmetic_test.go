package timev4

import (
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestArithmeticMatchesSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/time_arithmetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID, Operation   string
			Input, Expected map[string]string
			Error           string `json:"expected_error"`
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, v := range corpus.Vectors {
		// The runtime takes already decoded uint64 quantities; syntax failures
		// for decimal text belong to the separate shared wire consumers.
		if v.Error == "time_integer" {
			continue
		}
		checked++
		t.Run(v.ID, func(t *testing.T) {
			n := func(key string) uint64 {
				value, err := strconv.ParseUint(v.Input[key], 10, 64)
				if err != nil {
					t.Fatal(key, err)
				}
				return value
			}
			rate := Rate{n("rate_numerator"), n("rate_denominator"), n("quantization_ms")}
			result := map[string]string{}
			put := func(k string, n uint64) { result[k] = strconv.FormatUint(n, 10) }
			var err error
			switch v.Operation {
			case "elapsed":
				var lower, upper uint64
				lower, upper, err = rate.Elapsed(n("delta_ms"))
				put("elapsed_lower_ms", lower)
				put("elapsed_upper_ms", upper)
			case "network_anchor", "advance_anchor":
				var interval Interval
				if v.Operation == "network_anchor" {
					interval, err = rate.NetworkAnchor(n("sample_ms"), n("source_error_ms"), n("delta_ms"), n("max_round_trip_ms"), n("max_width_ms"))
				} else {
					interval, err = rate.Advance(Interval{n("lower_ms"), n("upper_ms")}, n("delta_ms"), n("max_age_ms"), n("max_width_ms"))
				}
				put("lower_ms", interval.LowerMS)
				put("upper_ms", interval.UpperMS)
			case "deadline_delta", "prove_delta":
				var delta uint64
				if v.Operation == "deadline_delta" {
					delta, err = rate.DeadlineDelta(n("upper_ms"), n("deadline_ms"))
				} else {
					delta, err = rate.ProveDelta(n("lower_ms"), n("bound_ms"))
				}
				put("delta_ms", delta)
			default:
				t.Fatal("unknown operation", v.Operation)
			}
			if v.Error != "" {
				if err == nil || err.Error() != v.Error {
					t.Fatal(result, err, v.Error)
				}
			} else if err != nil || !reflect.DeepEqual(result, v.Expected) {
				t.Fatal(result, err, v.Expected)
			}
		})
	}
	if checked != 35 {
		t.Fatal("incomplete arithmetic corpus", checked)
	}
}
