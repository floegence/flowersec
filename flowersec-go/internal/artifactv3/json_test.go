package artifactv3

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCanonicalJSONEmitsJCSLineSeparatorsWithoutRewritingLiteralEscapes(t *testing.T) {
	value := struct {
		Text string `json:"text"`
	}{Text: "left\u2028middle\u2029right|\\u2028|\\u2029|\\" + string(rune(0x2028))}

	got, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("{\"text\":\"left" + string(rune(0x2028)) + "middle" + string(rune(0x2029)) +
		"right|\\\\u2028|\\\\u2029|\\\\" + string(rune(0x2028)) + "\"}")
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical JSON = %q, want %q", got, want)
	}
}

func TestCanonicalScopedPayloadRequiresLiteralJCSLineSeparators(t *testing.T) {
	canonical := []byte("{\"escaped\":\"\\\\u2028\",\"literal\":\"" + string(rune(0x2028)) + "\"}")
	if err := validateCanonicalScopedPayload(canonical); err != nil {
		t.Fatalf("literal JCS line separator rejected: %v", err)
	}
	noncanonical := []byte("{\"escaped\":\"\\\\u2028\",\"literal\":\"\\u2028\"}")
	if err := validateCanonicalScopedPayload(noncanonical); err == nil {
		t.Fatal("escaped U+2028 was accepted as canonical JCS")
	}
}

func TestScopedPayloadPreflightRejectsNestedDuplicateKeys(t *testing.T) {
	err := preflightScopedPayload([]byte(`{"outer":{"value":1,"value":2}}`))
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON field "value"`) {
		t.Fatalf("nested duplicate error = %v", err)
	}
}

func TestScopedPayloadPreflightDepthAndNodeBoundaries(t *testing.T) {
	nested := func(objectDepth int) []byte {
		value := "0"
		for depth := 0; depth < objectDepth; depth++ {
			value = `{"a":` + value + `}`
		}
		return []byte(value)
	}
	nodeBoundary := func(scalarNodes int) []byte {
		lengths := []int{63, 63, 63, scalarNodes - 189}
		arrays := make([]string, len(lengths))
		for index, length := range lengths {
			values := make([]string, length)
			for valueIndex := range values {
				values[valueIndex] = "0"
			}
			arrays[index] = `[` + strings.Join(values, `,`) + `]`
		}
		return []byte(fmt.Sprintf(`{"a":%s,"b":%s,"c":%s,"d":%s}`, arrays[0], arrays[1], arrays[2], arrays[3]))
	}

	if err := preflightScopedPayload(nested(15)); err != nil {
		t.Fatalf("depth 16 rejected: %v", err)
	}
	if err := preflightScopedPayload(nested(16)); err == nil || !strings.Contains(err.Error(), "depth exceeds 16") {
		t.Fatalf("depth 17 error = %v", err)
	}
	if err := preflightScopedPayload(nodeBoundary(251)); err != nil {
		t.Fatalf("256 nodes rejected: %v", err)
	}
	if err := preflightScopedPayload(nodeBoundary(252)); err == nil || !strings.Contains(err.Error(), "node count exceeds 256") {
		t.Fatalf("257 nodes error = %v", err)
	}
}

func TestScopedPayloadPreflightCollectionAndScalarLimits(t *testing.T) {
	members := make([]string, 65)
	for index := range members {
		members[index] = fmt.Sprintf(`"k%d":0`, index)
	}
	values := make([]string, 65)
	for index := range values {
		values[index] = "0"
	}
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "members", raw: `{` + strings.Join(members, `,`) + `}`, want: "object exceeds 64 members"},
		{name: "elements", raw: `{"a":[` + strings.Join(values, `,`) + `]}`, want: "array exceeds 64 elements"},
		{name: "key", raw: `{"` + strings.Repeat("k", 129) + `":0}`, want: "key exceeds 128 bytes"},
		{name: "string", raw: `{"a":"` + strings.Repeat("v", 1_025) + `"}`, want: "string exceeds 1024 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := preflightScopedPayload([]byte(test.raw)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSessionInitExpiryUsesSafeIntegerRange(t *testing.T) {
	valid := SessionContract{
		ChannelID:                     "channel",
		InitExpireAtUnixSeconds:       maxSignedSafeInteger,
		EstablishTimeoutSeconds:       30,
		RekeyPrepareTimeoutSeconds:    10,
		RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams:             1,
		AllowedSuites:                 []uint16{1},
		DefaultSuite:                  1,
	}
	if _, _, err := ComputeSessionContractHash(valid); err != nil {
		t.Fatalf("maximum safe init expiry rejected: %v", err)
	}
	valid.InitExpireAtUnixSeconds++
	if _, _, err := ComputeSessionContractHash(valid); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("unsafe init expiry error = %v, want %v", err, ErrInvalidArtifact)
	}
}
