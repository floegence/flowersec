// Package idna15 freezes Flowersec host normalization to Unicode 15.1 and
// UTS #46 non-transitional processing with STD3 and DNS length checks.
package idna15

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

const UnicodeVersion = "15.1.0"

var ErrInvalidHost = errors.New("invalid Unicode 15.1 IDNA host")

var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.ValidateLabels(true),
	idna.CheckHyphens(true),
	idna.CheckJoiners(true),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

// LookupASCII returns a lowercase A-label host. x/net currently freezes
// Unicode 15.0; Unicode 15.1 added only U+2EBF0..U+2EE5D to the UTS #46 valid
// set. The fallback substitutes an equivalent existing CJK code point while
// x/net performs mapping, normalization, Bidi, ContextJ, and label validation,
// then restores and Punycode-encodes the committed 15.1 code points.
func LookupASCII(host string) (string, error) {
	if host == "" || strings.HasSuffix(host, ".") {
		return "", ErrInvalidHost
	}
	if ascii, err := lookupProfile.ToASCII(host); err == nil && ascii != "" && !strings.HasSuffix(ascii, ".") {
		return strings.ToLower(ascii), nil
	}
	return lookupUnicode15_1Delta(host)
}

func lookupUnicode15_1Delta(host string) (string, error) {
	decodedLabels := strings.Split(host, ".")
	originalALabels := make(map[int]string)
	deltaCount := 0
	for index, label := range decodedLabels {
		if strings.HasPrefix(strings.ToLower(label), "xn--") {
			decoded, err := idna.Punycode.ToUnicode(strings.ToLower(label))
			if err != nil {
				return "", ErrInvalidHost
			}
			decodedLabels[index] = decoded
			originalALabels[index] = strings.ToLower(label)
		}
		for _, value := range decodedLabels[index] {
			if unicode15_1DeltaValid(value) {
				deltaCount++
			}
		}
	}
	if deltaCount == 0 {
		return "", ErrInvalidHost
	}
	decoded := strings.Join(decodedLabels, ".")
	placeholder, ok := choosePlaceholder(decoded)
	if !ok {
		return "", ErrInvalidHost
	}
	originalDelta := make([]rune, 0, deltaCount)
	var substituted strings.Builder
	for _, value := range decoded {
		if unicode15_1DeltaValid(value) {
			originalDelta = append(originalDelta, value)
			substituted.WriteRune(placeholder)
		} else {
			substituted.WriteRune(value)
		}
	}
	mapped, err := lookupProfile.ToUnicode(substituted.String())
	if err != nil || strings.Count(mapped, string(placeholder)) != len(originalDelta) {
		return "", ErrInvalidHost
	}
	var restored strings.Builder
	deltaIndex := 0
	for _, value := range mapped {
		if value == placeholder {
			restored.WriteRune(originalDelta[deltaIndex])
			deltaIndex++
		} else {
			restored.WriteRune(value)
		}
	}
	labels := strings.Split(restored.String(), ".")
	if len(labels) != len(decodedLabels) {
		return "", ErrInvalidHost
	}
	for index, label := range labels {
		if label == "" {
			return "", ErrInvalidHost
		}
		ascii, encodeErr := idna.Punycode.ToASCII(label)
		if encodeErr != nil {
			return "", ErrInvalidHost
		}
		ascii = strings.ToLower(ascii)
		if len(ascii) == 0 || len(ascii) > 63 {
			return "", ErrInvalidHost
		}
		if original, exists := originalALabels[index]; exists && original != ascii {
			return "", ErrInvalidHost
		}
		labels[index] = ascii
	}
	ascii := strings.Join(labels, ".")
	if len(ascii) == 0 || len(ascii) > 253 || strings.HasSuffix(ascii, ".") {
		return "", ErrInvalidHost
	}
	return ascii, nil
}

func unicode15_1DeltaValid(value rune) bool {
	return value >= '\U0002ebf0' && value <= '\U0002ee5d'
}

func choosePlaceholder(value string) (rune, bool) {
	for candidate := rune(0x4e00); candidate <= 0x9fff; candidate++ {
		if !strings.ContainsRune(value, candidate) {
			return candidate, true
		}
	}
	return 0, false
}
