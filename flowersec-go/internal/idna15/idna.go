// Package idna15 freezes Flowersec host normalization to Unicode 15.1 and
// UTS #46 non-transitional processing with STD3 and DNS length checks.
package idna15

import (
	"errors"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/unicode151"
	"golang.org/x/net/idna"
)

const UnicodeVersion = unicode151.Version

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

// LookupASCII returns a lowercase A-label host. The repository-owned Unicode
// 15.1 table limits both U-label input and decoded A-labels before the current
// x/net implementation performs normalization, Punycode, Bidi, and ContextJ.
func LookupASCII(host string) (string, error) {
	if host == "" || strings.HasSuffix(host, ".") || !assigned(host) {
		return "", ErrInvalidHost
	}
	decoded, err := lookupProfile.ToUnicode(host)
	if err != nil || decoded == "" || !assigned(decoded) {
		return "", ErrInvalidHost
	}
	ascii, err := lookupProfile.ToASCII(host)
	if err != nil || ascii == "" || strings.HasSuffix(ascii, ".") {
		return "", ErrInvalidHost
	}
	return strings.ToLower(ascii), nil
}

func assigned(value string) bool {
	for _, scalar := range value {
		if !unicode151.Assigned(scalar) {
			return false
		}
	}
	return true
}
