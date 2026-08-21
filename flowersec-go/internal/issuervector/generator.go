// Package issuervector provides the internal executable boundary for the
// shared Go issuer admission fixture. The production control-plane package
// registers the generator so deterministic test dependencies never become
// part of Flowersec's public issuer API.
package issuervector

import (
	"errors"
	"sync"
)

var ErrGeneratorUnavailable = errors.New("Flowersec issuer vector generator is unavailable")

var (
	generatorMu sync.Mutex
	generator   func() ([]byte, error)
)

// Register installs the production control-plane fixture generator exactly
// once during package initialization.
func Register(current func() ([]byte, error)) {
	if current == nil {
		panic(ErrGeneratorUnavailable)
	}
	generatorMu.Lock()
	defer generatorMu.Unlock()
	if generator != nil {
		panic("Flowersec issuer vector generator registered twice")
	}
	generator = current
}

// Generate invokes the production control-plane fixture generator.
func Generate() ([]byte, error) {
	generatorMu.Lock()
	current := generator
	generatorMu.Unlock()
	if current == nil {
		return nil, ErrGeneratorUnavailable
	}
	return current()
}
