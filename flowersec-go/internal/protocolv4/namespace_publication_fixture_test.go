package protocolv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespacePublicationTestHarness exposes signed fixture material to external
// storage/assembly tests; it is compiled only into the test binary.
type NamespacePublicationTestHarness struct {
	Clock          *timev4.Clock
	Trust          *NamespaceTrustStore
	Scope          NamespacePublicationScope
	Signer         MapSigner
	RootSigner     MapSigner
	SignerID       [16]byte
	State, Changed []byte
	Environment    resourcev4.Reference
	Reserve        func(resourcev4.Vector) resourcev4.Reference
	Advance        func(uint64)
	RejectSigner   func()
}

func NewNamespacePublicationTestHarness(t *testing.T) *NamespacePublicationTestHarness {
	t.Helper()
	f := onlineBootstrap(t)
	// The control authority and online Head signer have separate real keys.
	f.seed = [32]byte{91, 12, 4}
	f.owner.root.PublicKey = testTrustPublic(f.seed)
	if err := f.owner.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	f.operation.Close()
	if err := f.operation.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	n := f.namespace
	r, err := f.owner.Rules()
	if err != nil {
		t.Fatal(err)
	}
	seed := [32]byte{71, 23, 4}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
	h := &NamespacePublicationTestHarness{Clock: f.owner.clock, Trust: f.owner, Scope: r.PublicationScope(f.head.generation), Signer: signer, SignerID: f.head.signerID, State: bytes.Clone(f.state), Environment: n.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096}), Reserve: func(v resourcev4.Vector) resourcev4.Reference { return n.reserve(t, v) }, Advance: func(delta uint64) { f.tick.Add(delta) }}
	h.RootSigner = &admissionTestSigner{key: ed25519.NewKeyFromSeed(f.seed[:])}
	entry := n.mapValue(t, "RevokedLeaseEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(bytes.Repeat([]byte{0x31}, 16)), "lease_id": namespaceBytes(bytes.Repeat([]byte{0x41}, 16)), "artifact_digest": namespaceBytes(bytes.Repeat([]byte{0x51}, 32)), "cohort": namespaceNumber(1), "latest_impact_not_after_ms": namespaceNumber(9000)})
	n.set(t, "RevocationState", n.state, "revoked_leases", namespaceArray(entry))
	h.Changed = n.state.encode(nil)
	h.RejectSigner = func() {
		f.advance(t, 2, 9000)
		f.set(t, "rejected_head_signers", namespaceArray(namespaceBytes(h.SignerID[:])))
		if err := f.owner.Update(f.wire(t)); err != nil {
			t.Fatal(err)
		}
	}
	return h
}
