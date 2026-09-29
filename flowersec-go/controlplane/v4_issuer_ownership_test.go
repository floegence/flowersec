package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Neither an allocated issuer nor an independent root alone grants issuance.
// These adapters fail the test if construction invokes application authority.
type unconfiguredIssueAuthority struct{ t *testing.T }

func (a unconfiguredIssueAuthority) BeginDirectIssue(context.Context, controlplane.V4DirectIssueRequest, controlplane.V4DirectIssueFacts) (controlplane.V4DirectIssuePermit, error) {
	a.t.Error("construction invoked the durable authority")
	return nil, context.Canceled
}
func (a unconfiguredIssueAuthority) BeginArtifactIssue(context.Context, controlplane.V4ArtifactIssueRequest, controlplane.V4ArtifactIssueFacts) (controlplane.V4ArtifactIssuePermit, error) {
	a.t.Error("construction invoked the durable authority")
	return nil, context.Canceled
}

type unconfiguredIssueSigner struct {
	t   *testing.T
	key ed25519.PrivateKey
}

func (s unconfiguredIssueSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }
func (s unconfiguredIssueSigner) Sign([]byte) ([]byte, error) {
	s.t.Error("unconfigured issuer signed material")
	return nil, context.Canceled
}

func TestV4IssuerConstructionRetainsCallerOwnershipAndRefundsRefusal(t *testing.T) {
	f := newControlResources(t)
	seed := [32]byte{23}
	signer := unconfiguredIssueSigner{t, ed25519.NewKeyFromSeed(seed[:])}
	limits := protocolv4.NamespaceTrustLimits{Configurations: 2, ConfigBytes: 8192, MapNodes: 4096, RuntimeBytes: 4096}
	cost, err := protocolv4.NamespaceTrustCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := f.environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := protocolv4.NewNamespaceTrustAnchor(protocolv4.NamespaceTrustRoot{Tenant: "tenant", Authority: "authority", KeyID: [16]byte{1}, PublicKey: [32]byte(signer.PublicKey()), MaxLifetimeMS: 10000}, limits, f.clock, f.reserve(cost), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		trust.Close()
		if err := trust.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	base := controlplane.V4DirectIssuerConfig{
		Clock: f.clock, Trust: [3]*protocolv4.NamespaceTrustStore{trust, trust, trust}, Signer: signer,
		IssuerKeyID: [16]byte{1}, Tenant: "tenant", Audience: "service", CryptoProfile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", RevocationPolicyID: "online",
		Generation: 1, RevocationPolicyRevision: 1, ClientCertificate: []byte{0xa0}, ServerCertificate: []byte{0xa0}, Candidates: [][]byte{{0xa0}}, SessionContract: []byte{0xa0}, ResumePolicy: []byte{0xa0},
		InitiationLifetimeMS: 300, SessionLifetimeMS: 800, MaxAuthenticationBytes: 128, WorkMS: 1000, RuntimeBytes: 8192,
	}
	authority := unconfiguredIssueAuthority{t}
	direct := base
	direct.Authority = authority
	artifact := controlplane.V4ArtifactIssuerConfig{Base: base, Authority: authority}
	for _, tc := range []struct {
		name      string
		charge    func() (resourcev4.Vector, error)
		construct func(resourcev4.Reference) error
	}{
		{"direct", func() (resourcev4.Vector, error) { return controlplane.V4DirectIssuerCharge(direct) }, func(ref resourcev4.Reference) error {
			issuer, err := controlplane.NewV4DirectIssuer(direct, ref, f.environment)
			if issuer != nil {
				t.Fatal("empty trust configuration authorized issuer")
			}
			return err
		}},
		{"artifact", func() (resourcev4.Vector, error) { return controlplane.V4ArtifactIssuerCharge(artifact) }, func(ref resourcev4.Reference) error {
			issuer, err := controlplane.NewV4ArtifactIssuer(artifact, ref, f.environment)
			if issuer != nil {
				t.Fatal("empty trust configuration authorized issuer")
			}
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			charge, err := tc.charge()
			if err != nil {
				t.Fatal(err)
			}
			// Insufficient admission must leave the original reservation with
			// its caller, since no transfer was possible.
			short := charge
			short[resourcev4.SDKBytes]--
			ref := f.reserve(short)
			before := f.root.Snapshot()
			if err := tc.construct(ref); err != controlplane.V4IssueFailure("capacity_exhausted") {
				t.Fatal(err)
			}
			if after := f.root.Snapshot(); after != before || ref.Check() != nil {
				t.Fatal("failed admission consumed caller ownership", before, after)
			}
			ref.Release()
			// Once admitted, failure to resolve the original trust must release
			// the transferred owner and every intermediate trust borrow.
			before = f.root.Snapshot()
			ref = f.reserve(charge)
			if err := tc.construct(ref); err != controlplane.V4IssueFailure("issuance_refused") {
				t.Fatal("untrusted issuance was not refused", err)
			}
			if after := f.root.Snapshot(); after != before {
				t.Fatal("constructor refusal leaked a transferred owner", before, after)
			}
			if ref.Check() == nil {
				t.Fatal("stale caller handle survived ownership transfer")
			}
		})
	}
}

func TestV4LiveAuthorizationCodecPreservesOriginalInvocation(t *testing.T) {
	f := newControlResources(t)
	backing, err := controlplane.V4LiveAuthorizationCodecBackingBytes()
	if err != nil || backing == 0 {
		t.Fatal(backing, err)
	}
	f.reserve(resourcev4.Vector{resourcev4.SDKBytes: backing})
	codec, err := controlplane.NewV4LiveAuthorizationCodec()
	if err != nil {
		t.Fatal(err)
	}
	q := controlplane.V4LiveAuthorizationRequest{Tenant: "tenant", Audience: "listener", CryptoProfile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", Issuer: [16]byte{1}, Lease: [16]byte{2}, Attempt: [16]byte{3}, Artifact: [32]byte{4}, ClientIdentity: [32]byte{5}, ServerIdentity: [32]byte{6}, Winner: protocolv4.PoolMember{Index: 15, CandidateID: [16]byte{7}, RouteDigest: [32]byte{8}}, ActivationNotAfterMS: 10000, AttemptNo: 1}
	for _, profile := range []string{"fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"} {
		q.CryptoProfile = profile
		buffer := make([]byte, 1024)
		n, err := controlplane.EncodeV4LiveAuthorizationRequest(buffer, q)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := codec.Decode(buffer[:n]); err != nil || got != q {
			t.Fatal("original invocation projection changed", got, err)
		}
		if _, err := codec.Decode(append(buffer[:n:n], 0)); err == nil {
			t.Fatal("trailing bytes accepted")
		}
		q.AttemptNo = 2
		if n, err := controlplane.EncodeV4LiveAuthorizationRequest(buffer, q); err == nil || n != 0 {
			t.Fatal("new attempt represented as original invocation", n, err)
		}
		q.AttemptNo = 1
	}
}
