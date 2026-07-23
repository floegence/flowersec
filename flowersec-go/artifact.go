// Package flowersec exposes the carrier-neutral Flowersec v2 consumer API.
package flowersec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
)

// ErrInvalidArtifact reports an invalid or forged opaque artifact handle.
var ErrInvalidArtifact = errors.New("invalid Flowersec artifact")

// Artifact is an opaque, validated Flowersec v2 connection artifact.
// Its credentials, candidates, route, and session contract are intentionally
// unavailable to application code.
type Artifact struct {
	value *artifactv2.Artifact
}

// ParseArtifact strictly parses and validates one serialized Flowersec v2
// artifact. Unknown and duplicate JSON fields are rejected.
func ParseArtifact(encoded []byte) (Artifact, error) {
	value, err := artifactv2.DecodeArtifactJSON(bytes.NewReader(encoded))
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: malformed input", ErrInvalidArtifact)
	}
	return Artifact{value: value}, nil
}

// String deliberately reveals no artifact contents.
func (Artifact) String() string { return "Flowersec.Artifact" }

// GoString deliberately reveals no artifact contents in detailed formatting.
func (Artifact) GoString() string { return "flowersec.Artifact" }

// MarshalJSON preserves opacity when an artifact is passed to a generic JSON
// boundary. Serialized artifacts are accepted only by ParseArtifact.
func (Artifact) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ArtifactLease binds an opaque artifact to the application's durable spend
// callback. It exposes neither the artifact payload nor the callback.
type ArtifactLease struct {
	artifact    Artifact
	commitSpend func(context.Context) error
}

// NewArtifactLease creates a single-use connection lease. commitSpend must
// durably record SPENT before returning nil.
func NewArtifactLease(artifact Artifact, commitSpend func(context.Context) error) (ArtifactLease, error) {
	if artifact.value == nil || commitSpend == nil {
		return ArtifactLease{}, ErrInvalidArtifact
	}
	return ArtifactLease{artifact: artifact, commitSpend: commitSpend}, nil
}

// MarshalJSON prevents generic serialization from exposing lease internals.
func (ArtifactLease) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var _ json.Marshaler = Artifact{}
var _ json.Marshaler = ArtifactLease{}
