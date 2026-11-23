package protocolv4

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRuntimeCBORCompleteMapCorpus(t *testing.T) {
	vectors := cborRefVectors(t)
	maximum := 1
	for _, v := range vectors {
		if len(v.Hex)/2 > maximum {
			maximum = len(v.Hex) / 2
		}
	}
	d, err := NewDecoder(maximum, maximum*2)
	if err != nil {
		t.Fatal(err)
	}
	positive, negative := 0, 0
	for _, v := range vectors {
		// These two require the independently retained containing object. Their
		// actual owners compare original pool membership/OPEN bytes separately.
		if v.ExpectedError == "pool_set_membership" || v.ExpectedError == "open_digest_mismatch" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			input := oracleBytes(t, v.Hex)
			original := bytes.Clone(input)
			shape := shapeContext(v.Limits)
			doc, err := d.DecodeMap(input, v.Schema, DecodeContext{Limits: shape.limits, Selectors: shape.selectors})
			if !bytes.Equal(input, original) {
				t.Fatal("input modified")
			}
			if v.ExpectedError != "" {
				negative++
				if err == nil {
					doc.Release()
					t.Fatal("accepted invalid map", v.ExpectedError)
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			defer doc.Release()
			clear(input)
			if !bytes.Equal(doc.Bytes(), original) {
				t.Fatal("original bytes replaced")
			}
		})
	}
	if positive != 337 || negative == 0 {
		t.Fatal("incomplete corpus", positive, negative)
	}
}

func TestRuntimeSignedHostAndOriginCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/text.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID, Operation, Input string
			ExpectedError        string `json:"expected_error"`
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	r, err := runtimeRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		if v.Operation != "wire_host" && v.Operation != "wire_origin" && v.Operation != "wire_dns" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			var err error
			if v.Operation == "wire_origin" {
				err = r.originText(v.Input)
			} else {
				err = wireHostText(v.Input)
			}
			if (err != nil) != (v.ExpectedError != "") {
				t.Fatal("unexpected wire text acceptance", err, v.ExpectedError)
			}
		})
	}
}

func TestRuntimeSignedHostRejectsInvalidALabelClaims(t *testing.T) {
	for _, label := range []string{"a·b", "😀", "a\u200cb", "aא"} {
		puny, err := punyEncode([]rune(label))
		if err != nil {
			t.Fatal(err)
		}
		if err := wireHostText("xn--" + puny + ".example"); err == nil {
			t.Errorf("invalid original A-label accepted: %q", label)
		}
	}
	if err := wireHostText("1.xn--mgbh0fb"); err == nil {
		t.Error("domain-level Bidi rule omitted")
	}
}

func TestRuntimeWireDNSPinnedConformanceOutputs(t *testing.T) {
	// The official corpus also includes inputs that UTS46 can map but which
	// the wire profile must reject under IDNA2008/assigned-code-point rules.
	// Compare exact original ASCII output candidates against the independent
	// pinned reference, without using that oracle in production.
	r := newIDNAReference(t, newCBORReference(t))
	raw, err := os.ReadFile("../../../testdata/unicode15_1/IdnaTestV2.txt")
	if err != nil {
		t.Fatal(err)
	}
	var workspace wireIDNAWorkspace
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		columns := strings.Split(line, ";")
		if len(columns) < 5 {
			t.Fatal("invalid corpus")
		}
		for i := range columns {
			columns[i] = idnaUnescape(strings.TrimSpace(columns[i]))
		}
		candidate := columns[3]
		if candidate == "" {
			candidate = columns[1]
		}
		if candidate == "" {
			candidate = columns[0]
		}
		expected := r.wireDNS(candidate)
		actual := wireDNS(candidate, &workspace)
		if (expected == nil) != (actual == nil) {
			t.Fatalf("case %d: %q: runtime %v; reference %v", count, candidate, actual, expected)
		}
		count++
	}
	if count != 6265 {
		t.Fatal("incomplete pinned corpus", count)
	}
}
