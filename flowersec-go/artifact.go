// Package flowersec exposes the carrier-neutral Flowersec v3 consumer API.
package flowersec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

// ErrInvalidArtifact reports an invalid or forged opaque artifact handle.
var ErrInvalidArtifact = errors.New("invalid Flowersec artifact")

// Artifact is an opaque, validated Flowersec v3 connection artifact.
// Its credentials, candidates, route, and session contract are intentionally
// unavailable to application code.
type Artifact struct {
	value *artifactv3.Artifact
}

// ParseArtifact strictly parses and validates one serialized Flowersec v3
// artifact. Unknown and duplicate JSON fields are rejected.
func ParseArtifact(encoded []byte) (Artifact, error) {
	value, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(encoded))
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
	artifact Artifact
	state    *artifactLeaseState
}

var errArtifactLeaseConsumed = errors.New("Flowersec artifact lease is unavailable")

type artifactLeaseStatus uint8

const (
	artifactLeaseIdle artifactLeaseStatus = iota
	artifactLeaseClaimed
	artifactLeaseSpending
	artifactLeaseConsumed
	artifactLeaseRetired
)

type artifactLeaseState struct {
	mu          sync.Mutex
	status      artifactLeaseStatus
	commitSpend func(context.Context) error
	retire      func(context.Context) error
}

// claimedArtifactLease is the package-private proof that exactly one caller
// owns the lease state machine. It cannot be constructed through the public
// API, so the one-shot connector and ConnectionController share one claim
// boundary without racing each other.
type claimedArtifactLease struct {
	lease ArtifactLease
}

func (lease ArtifactLease) present() bool {
	return lease.artifact.value != nil || lease.state != nil
}

func (lease ArtifactLease) claimArtifact() (claimedArtifactLease, bool) {
	if lease.state == nil {
		return claimedArtifactLease{}, false
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	if lease.state.status != artifactLeaseIdle {
		return claimedArtifactLease{}, false
	}
	lease.state.status = artifactLeaseClaimed
	return claimedArtifactLease{lease: lease}, true
}

// claimForConnectionController is retained for package-local compatibility
// with existing one-shot lease tests. New connection paths use claimArtifact
// so the claimed proof is carried explicitly.
func (lease ArtifactLease) claimForConnectionController() bool {
	_, ok := lease.claimArtifact()
	return ok
}

func (claimed claimedArtifactLease) valid() bool {
	return claimed.lease.artifact.value != nil && claimed.lease.state != nil
}

func (claimed claimedArtifactLease) spendStarted() bool {
	if claimed.lease.state == nil {
		return false
	}
	claimed.lease.state.mu.Lock()
	defer claimed.lease.state.mu.Unlock()
	return claimed.lease.state.status == artifactLeaseSpending || claimed.lease.state.status == artifactLeaseConsumed
}

func (claimed claimedArtifactLease) retire(ctx context.Context) error {
	return claimed.lease.retire(ctx)
}

// String deliberately reveals no artifact or callback contents.
func (ArtifactLease) String() string { return "Flowersec.ArtifactLease" }

// GoString deliberately reveals no artifact or callback contents.
func (ArtifactLease) GoString() string { return "flowersec.ArtifactLease" }

// NewArtifactLease creates a single-use connection lease. commitSpend must
// durably record SPENT before returning nil.
func NewArtifactLease(artifact Artifact, commitSpend func(context.Context) error) (ArtifactLease, error) {
	return NewArtifactLeaseWithRetirement(artifact, commitSpend, func(context.Context) error { return nil })
}

// NewArtifactLeaseWithRetirement creates a single-use lease whose owner can
// durably release an unused credential after a pre-spend failure.
func NewArtifactLeaseWithRetirement(
	artifact Artifact,
	commitSpend func(context.Context) error,
	retire func(context.Context) error,
) (ArtifactLease, error) {
	if artifact.value == nil || commitSpend == nil || retire == nil {
		return ArtifactLease{}, ErrInvalidArtifact
	}
	return ArtifactLease{
		artifact: artifact,
		state:    &artifactLeaseState{commitSpend: commitSpend, retire: retire},
	}, nil
}

func (lease ArtifactLease) commitSpend(ctx context.Context) error {
	if lease.state == nil || lease.state.commitSpend == nil {
		return ErrInvalidArtifact
	}
	lease.state.mu.Lock()
	if lease.state.status != artifactLeaseClaimed {
		lease.state.mu.Unlock()
		return errArtifactLeaseConsumed
	}
	lease.state.status = artifactLeaseSpending
	lease.state.mu.Unlock()

	err := lease.state.commitSpend(ctx)
	lease.state.mu.Lock()
	lease.state.status = artifactLeaseConsumed
	lease.state.mu.Unlock()
	return err
}

func (lease ArtifactLease) retire(ctx context.Context) error {
	if lease.state == nil || lease.state.retire == nil {
		return ErrInvalidArtifact
	}
	lease.state.mu.Lock()
	if lease.state.status != artifactLeaseClaimed {
		lease.state.mu.Unlock()
		return nil
	}
	lease.state.status = artifactLeaseRetired
	lease.state.mu.Unlock()
	return lease.state.retire(ctx)
}

// MarshalJSON prevents generic serialization from exposing lease internals.
func (ArtifactLease) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var _ json.Marshaler = Artifact{}
var _ json.Marshaler = ArtifactLease{}
