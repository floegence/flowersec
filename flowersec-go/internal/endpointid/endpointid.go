package endpointid

import (
	"crypto/rand"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/internal/base64url"
)

var (
	errInvalid    = errors.New("invalid endpoint instance id")
	errInvalidLen = errors.New("invalid length")
)

func Validate(eid string) error {
	b, err := base64url.Decode(eid)
	if err != nil {
		return errInvalid
	}
	if len(b) < 16 || len(b) > 32 {
		return errInvalid
	}
	return nil
}

func Random(n int) (string, error) {
	if n <= 0 {
		return "", errInvalidLen
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64url.Encode(b), nil
}
