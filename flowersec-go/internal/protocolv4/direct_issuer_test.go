package protocolv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type directIssuerTestAuthority struct {
	facts                []DirectIssueFacts
	digests              [][32]byte
	closed               int
	reject, rejectCommit bool
}

func (a *directIssuerTestAuthority) BeginDirectIssue(_ context.Context, request DirectIssueRequest, facts DirectIssueFacts) (DirectIssuePermit, error) {
	if a.reject || request.RequestID == ([32]byte{}) || !bytes.Equal(request.Authentication, []byte("authenticated host request")) {
		return nil, errors.New("authentication refused")
	}
	a.facts = append(a.facts, facts)
	return a, nil
}
func (*directIssuerTestAuthority) Check(ctx context.Context) error { return ctx.Err() }
func (a *directIssuerTestAuthority) Commit(_ context.Context, digest [32]byte) error {
	if a.rejectCommit {
		return errors.New("commit outcome unknown")
	}
	a.digests = append(a.digests, digest)
	return nil
}
func (a *directIssuerTestAuthority) Close() { a.closed++ }

type directIssuerFixture struct {
	s         *DirectIssuer
	c         DirectIssuerConfig
	f         *onlineBootstrapFixture
	authority *directIssuerTestAuthority
	signer    *admissionTestSigner
}

func directIssuerFixtureFor(t *testing.T, local bool, configure ...func(*onlineBootstrapFixture)) *directIssuerFixture {
	t.Helper()
	x := newEndpointCredentialFixture(t, false, false)
	// The reference durable issuer intentionally owns one purpose-specific
	// issuer authorization; certificate obligations have their own issuers.
	for i := 1; i < 3; i++ {
		wire, _ := x.originals[i].Bytes()
		certificate, _, err := x.f.r.decode(wire, "IdentityCertificate", nil, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		x.f.set(t, "IdentityCertificate", certificate, "issuer_key_id", namespaceBytes(bytes.Repeat([]byte{byte(0x30 + i)}, 16)))
		x.originals[i] = signRuntimeFixture(t, "IdentityCertificate", certificate.encode(nil), DecodeContext{})
	}
	credentials := [3]*Credential{}
	for i, original := range x.originals[:3] {
		var err error
		credentials[i], err = original.DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
	}
	f := onlineBootstrapConfigured(t, nil, func(f *onlineBootstrapFixture) {
		n := f.namespace
		issuers := make([]*cborRefValue, 3)
		for i, credential := range credentials {
			scope := credential.scope
			kind := uint64(0)
			affected := namespaceArray(namespaceNumber(100), &cborRefValue{major: 7, n: 22})
			if i == 0 {
				kind = 1
				affected = namespaceArray(&cborRefValue{major: 7, n: 22}, namespaceNumber(100))
			}
			fields := map[string]*cborRefValue{
				"authorization_id": namespaceBytes(bytes.Repeat([]byte{byte(i + 1)}, 16)), "tenant_id": namespaceText(scope.Tenant), "revocation_authority_id": namespaceText(scope.Authority), "namespace_capacity_digest": namespaceBytes(scope.CapacityDigest[:]), "authority_generation": namespaceNumber(scope.Generation), "credential_kind": namespaceNumber(kind), "issuer_key_id": namespaceBytes(scope.Issuer[:]), "issuer_public_key": namespaceBytes(credential.key[:]), "audience": namespaceText(scope.Audience), "signing_not_before_ms": namespaceNumber(1000), "signing_not_after_ms": namespaceNumber(5000), "first_cohort": namespaceNumber(0), "last_cohort": namespaceNumber(100), "max_credential_not_after_ms": namespaceNumber(6000), "max_affected_cohorts": affected, "crypto_profile_id": namespaceText(scope.Profile),
			}
			if i != 0 {
				fields["subject_id"] = namespaceText(scope.Subject)
				fields["role"] = namespaceNumber(scope.Role)
			}
			issuers[i] = n.mapValue(t, "CredentialIssuerAuthorization", fields)
		}
		f.set(t, "issuer_authorizations", namespaceArray(issuers...))
		for _, setup := range configure {
			setup(f)
		}
	})
	if _, err := f.operation.Run(context.Background(), f.provider); err != nil {
		t.Fatal(err)
	}
	if err := f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	client, _ := x.originals[1].Bytes()
	server, _ := x.originals[2].Bytes()
	candidate := x.candidate
	if local {
		localArtifact := x.f.seed(t, "artifact_local_fields")
		candidate = oracleField(t, x.f.r.cborReference, "Artifact", localArtifact, "candidates").items[0]
		x.f.set(t, "Candidate", candidate, "revocation_namespace_refs", oracleField(t, x.f.r.cborReference, "Candidate", x.candidate, "revocation_namespace_refs"))
	}
	scope := credentials[0].scope
	seed := [32]byte{71, 23, 4}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
	authority := &directIssuerTestAuthority{}
	c := DirectIssuerConfig{Clock: f.owner.clock, Trust: [3]*NamespaceTrustStore{f.owner, f.owner, f.owner}, Signer: signer, Authority: authority, IssuerKeyID: scope.Issuer, Tenant: scope.Tenant, Audience: scope.Audience, CryptoProfile: scope.Profile, RevocationPolicyID: "online", Generation: scope.Generation, RevocationPolicyRevision: 1, ClientCertificate: client, ServerCertificate: server, Candidates: [][]byte{candidate.encode(nil)}, SessionContract: oracleField(t, x.f.r.cborReference, "Artifact", x.parent, "session_contract").encode(nil), ResumePolicy: oracleField(t, x.f.r.cborReference, "Artifact", x.parent, "resume_policy").encode(nil), InitiationLifetimeMS: 300, SessionLifetimeMS: 800, MaxAuthenticationBytes: 128, WorkMS: 2000, RuntimeBytes: 8192}
	charge, err := DirectIssuerCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := f.namespace.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096})
	s, err := NewDirectIssuer(c, f.namespace.reserve(t, charge), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		if err := s.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return &directIssuerFixture{s: s, c: c, f: f, authority: authority, signer: signer}
}

func directIssuerRequest() DirectIssueRequest {
	return DirectIssueRequest{RequestID: [32]byte{1}, Authentication: []byte("authenticated host request")}
}

func TestDirectIssuerSignsCanonicalFreshDirectAndLocalArtifacts(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "local"}[local], func(t *testing.T) {
			f := directIssuerFixtureFor(t, local)
			var previousLease [16]byte
			var previousNonce, previousPSK [32]byte
			for i := 0; i < 2; i++ {
				out := make([]byte, 65536)
				n, err := f.s.IssueArtifactBytes(context.Background(), directIssuerRequest(), out)
				if err != nil {
					t.Fatal(err)
				}
				codec, err := NewSignedMapCodec("Artifact", 65536, 16384)
				if err != nil {
					t.Fatal(err)
				}
				key := [32]byte(f.signer.PublicKey())
				signed, err := codec.Verify(out[:n], key, DecodeContext{})
				if err != nil {
					t.Fatal(err)
				}
				leaseBytes, _ := signed.Field("lease_id").ByteString()
				lease := [16]byte(leaseBytes)
				nonceBytes, _ := signed.Field("session_nonce").ByteString()
				nonce := [32]byte(nonceBytes)
				pskBytes, _ := signed.Field("e2ee_psk").ByteString()
				psk := [32]byte(pskBytes)
				if lease == ([16]byte{}) || nonce == ([32]byte{}) || psk == ([32]byte{}) || nonce == psk || lease == previousLease || nonce == previousNonce || psk == previousPSK {
					t.Fatal("reused or zero material")
				}
				previousLease, previousNonce, previousPSK = lease, nonce, psk
				facts := f.authority.facts[i]
				if facts.LeaseID != lease || facts.Scope.IssuedMS != 1100 || facts.Scope.Cohort != 1 || facts.Scope.ExpiresMS != 1900 || facts.NamespaceCount != 1 || facts.Namespaces[0].RoleMask != 3 {
					t.Fatal("wrong original issuance facts", facts)
				}
				digest, err := signed.Digest("artifact_digest")
				if err != nil || digest != f.authority.digests[i] {
					t.Fatal("commit did not bind signed bytes", err)
				}
				signed.Release()
				clear(out)
			}
			if f.authority.closed != 2 || f.signer.calls.Load() != 2 {
				t.Fatal("original permit or signer count")
			}
		})
	}
}

func TestDirectIssuerRefusesAuthorityAndLifetimeBeforeSigning(t *testing.T) {
	for _, reason := range []string{"authentication", "lifetime", "commit", "signature"} {
		t.Run(reason, func(t *testing.T) {
			f := directIssuerFixtureFor(t, false)
			switch reason {
			case "authentication":
				f.authority.reject = true
			case "lifetime":
				f.s.c.SessionLifetimeMS = 10000
			case "commit":
				f.authority.rejectCommit = true
			case "signature":
				f.signer.bad = true
			}
			out := bytes.Repeat([]byte{0xa5}, 65536)
			n, err := f.s.IssueArtifactBytes(context.Background(), directIssuerRequest(), out)
			if err == nil || n != 0 || !bytes.Equal(out, bytes.Repeat([]byte{0xa5}, 65536)) {
				t.Fatal("refused issue published secret bytes", err)
			}
			if (reason == "authentication" || reason == "lifetime") && f.signer.calls.Load() != 0 {
				t.Fatal("signed before authorization or impact checks")
			}
		})
	}
}

func TestDirectIssuerCancellationRetainsActualSignerAndCharge(t *testing.T) {
	f := directIssuerFixtureFor(t, false)
	f.signer.entered, f.signer.release = make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-f.signer.release:
		default:
			close(f.signer.release)
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, err := f.s.IssueArtifactBytes(context.Background(), directIssuerRequest(), make([]byte, 65536))
		done <- err
	}()
	select {
	case <-f.signer.entered:
	case err := <-done:
		t.Fatal("signer not entered", err)
	case <-time.After(2 * time.Second):
		t.Fatal("signer not entered")
	}
	before := f.f.namespace.resources.Snapshot()
	f.s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := f.s.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup preceded provider return", err)
	}
	if after := f.f.namespace.resources.Snapshot(); after != before {
		t.Fatal("cancel returned original provider charge")
	}
	if _, err := f.s.IssueArtifactBytes(context.Background(), directIssuerRequest(), make([]byte, 65536)); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed issuer accepted new work", err)
	}
	close(f.signer.release)
	if err := <-done; err == nil {
		t.Fatal("cancelled signer result published")
	}
	if err := f.s.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.authority.digests) != 0 || f.authority.closed != 1 {
		t.Fatal("cancelled signing committed or leaked invocation")
	}
}

// DirectIssueSQLiteTestHarness supplies real signed namespace/credential
// material to external adapter tests without a production trust injection API.
type DirectIssueSQLiteTestHarness struct {
	fixture     *directIssuerFixture
	Config      DirectIssuerConfig
	Facts       DirectIssueFacts
	Environment resourcev4.Reference
	Reserve     func(resourcev4.Vector) resourcev4.Reference
}

func NewDirectIssueSQLiteTestHarness(t *testing.T) *DirectIssueSQLiteTestHarness {
	f := directIssuerFixtureFor(t, false)
	if _, err := f.s.IssueArtifactBytes(context.Background(), directIssuerRequest(), make([]byte, 65536)); err != nil {
		t.Fatal(err)
	}
	f.s.Close()
	if err := f.s.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &DirectIssueSQLiteTestHarness{fixture: f, Config: f.c, Facts: f.authority.facts[0], Environment: f.f.namespace.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096}), Reserve: func(v resourcev4.Vector) resourcev4.Reference { return f.f.namespace.reserve(t, v) }}
}
