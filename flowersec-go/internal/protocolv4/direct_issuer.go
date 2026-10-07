package protocolv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// DirectIssueRequest contains a bounded original host authentication envelope.
// It cannot select identities, a tenant, a signing key, or an issuance policy.
type DirectIssueRequest struct {
	RequestID      [32]byte
	Authentication []byte
}

// DirectIssueFacts binds the durable issuance obligation before signing. The
// host authority must authenticate the request, enforce its shared issuance
// rate, authorize both verifiers to read every namespace, and atomically reserve
// the worst-case revocation entry, encoded bytes and complete issuer/cohort
// evidence in its real durable store. A local resource reservation is not that
// authority transaction. The facts carry no PSK or session nonce.
type DirectIssueFacts struct {
	Scope                          CredentialScope
	LeaseID                        [16]byte
	ClientIdentity, ServerIdentity [32]byte
	InitiationNotAfterMS           uint64
	RevocationPolicyID             string
	RevocationPolicyRevision       uint64
	Namespaces                     [MaxArtifactIssueNamespaces]NamespaceReference
	NamespaceCount                 uint8
}

// DirectIssueAuthority is installed by the trusted host, never a network
// request. Begin must finish its durable reservation before returning a permit.
// Implementations must share one original outstanding ledger across instances.
type DirectIssueAuthority interface {
	BeginDirectIssue(context.Context, DirectIssueRequest, DirectIssueFacts) (DirectIssuePermit, error)
}

// DirectIssuePermit owns the original durable reservation. Commit records the
// exact signed Artifact digest before publication. Close releases only actual
// invocation work: it must not discard the durable issuance obligation, even
// when signing, cancellation, commit acknowledgement or delivery fails. Its
// eventual retirement uses the original authority's proven maturity/floor.
type DirectIssuePermit interface {
	Check(context.Context) error
	Commit(context.Context, [32]byte) error
	Close()
}

// DirectIssuerConfig is immutable trusted host configuration. Candidate maps,
// SessionContract and ResumePolicy are canonical v4 CBOR, checked by the shared
// schema. Candidates are direct network or the exclusive local-loopback leg;
// their complete namespace closure must match the three actual credentials.
// Trust order is Artifact, client certificate, server certificate. All belong
// to the same original Clock and resource Environment. Spend proof, activation,
// provider qualification and production claims remain separate obligations.
type DirectIssuerConfig struct {
	Clock                                               *timev4.Clock
	Trust                                               [3]*NamespaceTrustStore
	Signer                                              MapSigner
	Authority                                           DirectIssueAuthority
	IssuerKeyID                                         [16]byte
	Tenant, Audience, CryptoProfile, RevocationPolicyID string
	Generation, RevocationPolicyRevision                uint64
	ClientCertificate, ServerCertificate                []byte
	Candidates                                          [][]byte
	SessionContract, ResumePolicy                       []byte
	AllowedFeatures, RequiredFeatures                   uint64
	InitiationLifetimeMS, SessionLifetimeMS             uint64
	MaxAuthenticationBytes                              uint32
	WorkMS, RuntimeBytes                                uint64
}

// DirectIssuer has one original signing/response slot and no waiter queue.
// Cancellation never frees that slot while a signer or authority still runs.
type DirectIssuer struct {
	mu                    sync.Mutex
	c                     DirectIssuerConfig
	reservation, shared   resourcev4.Reference
	trustRefs             [3]resourcev4.Reference
	codec                 *SignedMapCodec
	certificates          [2]*Credential
	rules                 *NamespaceRules
	tunnels               *artifactTunnelIssuance
	retention             ArtifactIssueRetention
	candidates            []byte
	authentication        []byte
	cancel                context.CancelFunc
	done                  chan struct{}
	busy, closed, cleaned bool
}

func DirectIssuerCharge(c DirectIssuerConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || c.Signer == nil || c.Authority == nil || c.IssuerKeyID == ([16]byte{}) || len(c.Tenant) == 0 || len(c.Tenant) > 128 || len(c.Audience) == 0 || len(c.Audience) > 128 || len(c.CryptoProfile) == 0 || len(c.CryptoProfile) > 128 || len(c.RevocationPolicyID) == 0 || len(c.RevocationPolicyID) > 128 || len(c.Candidates) == 0 || len(c.Candidates) > 16 || len(c.ClientCertificate) == 0 || len(c.ClientCertificate) > 8192 || len(c.ServerCertificate) == 0 || len(c.ServerCertificate) > 8192 || len(c.SessionContract) == 0 || len(c.SessionContract) > 57 || len(c.ResumePolicy) == 0 || len(c.ResumePolicy) > 23 || c.InitiationLifetimeMS == 0 || c.SessionLifetimeMS < c.InitiationLifetimeMS || c.MaxAuthenticationBytes == 0 || c.MaxAuthenticationBytes > 16384 || c.WorkMS == 0 || c.WorkMS > 2000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	total := 1
	for _, candidate := range c.Candidates {
		if len(candidate) == 0 || len(candidate) > 65536-total {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		total += len(candidate)
	}
	for _, trust := range c.Trust {
		if trust == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	codec, err := SignedMapBackingBytes("Artifact", 65536, 16384)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	identity, err := SignedMapBackingBytes("IdentityCertificate", 8192, 4096)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := DecoderBackingBytes(65536, 16384)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	credential, err := CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// Includes constructor parsers, retained maps, detached credentials, encoder
	// field vectors, maximum owned request and guarded per-call metadata.
	cost := uint64(unsafe.Sizeof(DirectIssuer{})) + codec + identity + decoder + 2*credential + 2*65536 + 8192 + 4*uint64(unsafe.Sizeof(Credential{})) + 4*uint64(unsafe.Sizeof(DirectIssueFacts{})) + 128*uint64(unsafe.Sizeof(Field{})) + uint64(c.MaxAuthenticationBytes)
	return (resourcev4.Vector{resourcev4.SDKBytes: cost, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewDirectIssuer(c DirectIssuerConfig, reservation, dependencies resourcev4.Reference) (_ *DirectIssuer, err error) {
	cost, err := DirectIssuerCharge(c)
	if err != nil {
		return nil, err
	}
	return newArtifactIssuerCore(c, nil, cost, reservation, dependencies)
}

func newArtifactIssuerCore(c DirectIssuerConfig, tunnels *[16]*ArtifactTunnelIssueConfig, cost resourcev4.Vector, reservation, dependencies resourcev4.Reference) (_ *DirectIssuer, err error) {
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	s := &DirectIssuer{c: c, reservation: owned, done: make(chan struct{})}
	defer func() {
		if err != nil {
			s.tunnels.release()
			for _, ref := range s.trustRefs {
				ref.Release()
			}
			s.shared.Release()
			s.reservation.Release()
		}
	}()
	s.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	for i, trust := range c.Trust {
		if trust.clock != c.Clock {
			return nil, resourcev4.ErrConfiguration
		}
		if err = s.reservation.CheckSameEnvironment(trust.reservation); err != nil {
			return nil, err
		}
		s.trustRefs[i], err = trust.reservation.Borrow()
		if err != nil {
			return nil, err
		}
	}
	s.rules, err = c.Trust[0].Rules()
	if err != nil {
		return nil, err
	}
	if s.rules.tenant != c.Tenant {
		return nil, CBORFailure("revocation_namespace_binding")
	}
	s.codec, err = NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		return nil, err
	}
	identityCodec, err := NewSignedMapCodec("IdentityCertificate", 8192, 4096)
	if err != nil {
		return nil, err
	}
	decoder, err := NewDecoder(65536, 16384)
	if err != nil {
		return nil, err
	}
	for i, wire := range [][]byte{c.ClientCertificate, c.ServerCertificate} {
		doc, e := decoder.DecodeMap(wire, "IdentityCertificate", DecodeContext{})
		if e != nil {
			return nil, e
		}
		id, _ := doc.Root().Named("IdentityCertificate", "issuer_key_id").ByteString()
		issuer := [16]byte(id)
		doc.Release()
		key, e := c.Trust[i+1].CredentialKey("IdentityCertificate", issuer)
		if e != nil {
			return nil, e
		}
		signed, e := identityCodec.Verify(wire, key, DecodeContext{})
		if e != nil {
			return nil, e
		}
		s.certificates[i], e = signed.DetachCredential()
		signed.Release()
		if e != nil {
			return nil, e
		}
		scope := s.certificates[i].scope
		if scope.Tenant != c.Tenant || scope.Audience != c.Audience || scope.Profile != c.CryptoProfile || scope.Role != uint64(i) {
			return nil, CBORFailure("credential_identity_binding")
		}
	}
	if s.certificates[0].facts.Digest == s.certificates[1].facts.Digest {
		return nil, CBORFailure("credential_identity_binding")
	}
	if tunnels != nil {
		if err = s.prepareArtifactTunnels(*tunnels, decoder, identityCodec); err != nil {
			return nil, err
		}
	}
	for _, part := range []struct {
		schema string
		wire   []byte
	}{{"SessionContract", c.SessionContract}, {"ResumePolicy", c.ResumePolicy}} {
		doc, e := decoder.DecodeMap(part.wire, part.schema, DecodeContext{})
		if e != nil {
			return nil, e
		}
		doc.Release()
	}
	s.c.SessionContract, s.c.ResumePolicy = bytes.Clone(c.SessionContract), bytes.Clone(c.ResumePolicy)
	s.c.Tenant, s.c.Audience, s.c.CryptoProfile, s.c.RevocationPolicyID = strings.Clone(c.Tenant), strings.Clone(c.Audience), strings.Clone(c.CryptoProfile), strings.Clone(c.RevocationPolicyID)
	s.c.ClientCertificate, s.c.ServerCertificate, s.c.Candidates = nil, nil, nil
	s.candidates = make([]byte, 65536)
	s.candidates[0] = 0x80 | byte(len(c.Candidates))
	n := 1
	for index, wire := range c.Candidates {
		doc, e := decoder.DecodeMap(wire, "Candidate", DecodeContext{})
		if e != nil {
			return nil, e
		}
		err = s.checkArtifactCandidate(index, doc.Root())
		doc.Release()
		if err != nil {
			return nil, err
		}
		n += copy(s.candidates[n:], wire)
	}
	s.candidates = s.candidates[:n]
	s.authentication = make([]byte, c.MaxAuthenticationBytes)
	return s, nil
}

func (s *DirectIssuer) namespaceClosure() (refs [MaxArtifactIssueNamespaces]NamespaceReference, count uint8) {
	if s.tunnels != nil {
		return s.tunnels.namespaces, s.tunnels.count
	}
	refs[0] = NamespaceReference{Tenant: s.c.Tenant, Authority: s.rules.authority, Generation: s.c.Generation, CapacityDigest: s.rules.capacityDigest, RoleMask: 3}
	count = 1
	for _, cert := range s.certificates {
		scope := cert.scope
		ref := NamespaceReference{Tenant: scope.Tenant, Authority: scope.Authority, Generation: scope.Generation, CapacityDigest: scope.CapacityDigest, RoleMask: 3}
		found := false
		for _, old := range refs[:count] {
			if old == ref {
				found = true
			}
		}
		if !found {
			refs[count] = ref
			count++
		}
	}
	return
}

func (s *DirectIssuer) checkCandidateClosure(candidate Value) error {
	refs, count := s.namespaceClosure()
	actual := candidate.Named("Candidate", "revocation_namespace_refs")
	if actual.Len() != int(count) {
		return CBORFailure("credential_namespace_binding")
	}
	for i := 0; i < actual.Len(); i++ {
		ref := namespaceReference(actual.Index(i))
		found := false
		for _, expected := range refs[:count] {
			if ref == expected {
				found = true
			}
		}
		if !found {
			return CBORFailure("credential_namespace_binding")
		}
	}
	return nil
}

func (s *DirectIssuer) checkCredential(c *Credential, trust *NamespaceTrustStore) error {
	validation, err := trust.ResolveCredential(c)
	if err != nil {
		return err
	}
	requirements := validation.Policy.Requirements()
	_, _, err = validation.Namespace.CheckDetachedCredential(c, validation.Issuer, requirements.StalenessMS, requirements.SignerLifetimeMS, c.scope.ExpiresMS)
	return err
}

func (s *DirectIssuer) check(ctx context.Context, window *timev4.Window, parent *Credential) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return resourcev4.ErrClosed
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if err := s.shared.Check(); err != nil {
		return err
	}
	for _, ref := range s.trustRefs {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	if err := window.Check(); err != nil {
		return err
	}
	for i, cert := range s.certificates {
		if err := s.checkCredential(cert, s.c.Trust[i+1]); err != nil {
			return err
		}
	}
	if err := s.checkArtifactTunnels(parent); err != nil {
		return err
	}
	if parent != nil {
		if err := s.checkCredential(parent, s.c.Trust[0]); err != nil {
			return err
		}
		binding, err := s.c.Trust[0].ResolveCredential(parent)
		if err != nil {
			return err
		}
		requirement := binding.Policy.Requirements()
		for i, cert := range s.certificates {
			identity, err := s.c.Trust[i+1].ResolveCredential(cert)
			if err != nil {
				return err
			}
			child := identity.Policy.Requirements()
			if requirement.StalenessMS > child.StalenessMS || requirement.SignerLifetimeMS > child.SignerLifetimeMS {
				return CBORFailure("credential_policy_parent_envelope")
			}
		}
		now, err := s.c.Clock.Sample()
		if err != nil {
			return err
		}
		return parent.CheckAdmission(now.Interval)
	}
	return nil
}

// IssueArtifactBytes writes one signed v4 Artifact to the caller's original
// reserved response buffer. It publishes only after durable obligation commit
// and a final current authorization check. The caller protects/erases this
// secret-bearing buffer and delivers it only through independent authentication.
func (s *DirectIssuer) IssueArtifactBytes(ctx context.Context, request DirectIssueRequest, dst []byte) (n int, err error) {
	if s == nil || ctx == nil || request.RequestID == ([32]byte{}) || len(request.Authentication) == 0 || len(dst) < 65536 {
		return 0, resourcev4.ErrConfiguration
	}
	if !s.mu.TryLock() {
		return 0, resourcev4.ErrCapacity
	}
	if s.closed {
		s.mu.Unlock()
		return 0, resourcev4.ErrClosed
	}
	if s.busy {
		s.mu.Unlock()
		return 0, resourcev4.ErrCapacity
	}
	if len(request.Authentication) > int(s.c.MaxAuthenticationBytes) {
		s.mu.Unlock()
		return 0, resourcev4.ErrConfiguration
	}
	s.busy = true
	call, cancel := context.WithTimeout(ctx, time.Duration(s.c.WorkMS)*time.Millisecond)
	s.cancel = cancel
	s.mu.Unlock()
	defer s.finish()
	window, err := timev4.NewWindow(s.c.Clock, s.c.WorkMS)
	if err != nil {
		return 0, err
	}
	if err = s.check(call, window, nil); err != nil {
		return 0, err
	}
	copy(s.authentication, request.Authentication)
	request.Authentication = s.authentication[:len(request.Authentication):len(request.Authentication)]
	defer clear(s.authentication)
	now, err := s.c.Clock.Sample()
	if err != nil {
		return 0, err
	}
	issued := now.LowerMS
	if issued < s.rules.origin || s.rules.duration == 0 || issued > math.MaxUint64-s.c.SessionLifetimeMS {
		return 0, CBORFailure("revocation_overflow")
	}
	scope := CredentialScope{Schema: "Artifact", Tenant: s.c.Tenant, Authority: s.rules.authority, Audience: s.c.Audience, Profile: s.c.CryptoProfile, CapacityDigest: s.rules.capacityDigest, Issuer: s.c.IssuerKeyID, Generation: s.c.Generation, Cohort: (issued - s.rules.origin) / s.rules.duration, IssuedMS: issued, ExpiresMS: issued + s.c.SessionLifetimeMS}
	key, err := s.c.Trust[0].CredentialKey("Artifact", s.c.IssuerKeyID)
	if err != nil {
		return 0, err
	}
	var lease [16]byte
	var nonce, psk [32]byte
	defer clear(nonce[:])
	defer clear(psk[:])
	for _, secret := range [][]byte{lease[:], nonce[:], psk[:]} {
		if _, err = io.ReadFull(rand.Reader, secret); err != nil {
			return 0, CBORFailure("issuance_entropy")
		}
		nonzero := byte(0)
		for _, b := range secret {
			nonzero |= b
		}
		if nonzero == 0 {
			return 0, CBORFailure("issuance_entropy")
		}
	}
	if nonce == psk {
		return 0, CBORFailure("issuance_entropy")
	}
	parent := &Credential{scope: scope, key: key, lease: lease, admissionEnd: issued + s.c.InitiationLifetimeMS, facts: CredentialStateFacts{Cohort: scope.Cohort, HardDeadlineMS: scope.ExpiresMS, PolicyID: s.c.RevocationPolicyID, PolicyRevision: s.c.RevocationPolicyRevision, class: 1}}
	for _, cert := range s.certificates {
		if scope.ExpiresMS > cert.scope.ExpiresMS {
			return 0, CBORFailure("credential_lifetime")
		}
	}
	if err = s.check(call, window, parent); err != nil {
		return 0, err
	}
	facts := DirectIssueFacts{Scope: scope, LeaseID: lease, ClientIdentity: s.certificates[0].facts.Digest, ServerIdentity: s.certificates[1].facts.Digest, InitiationNotAfterMS: parent.admissionEnd, RevocationPolicyID: s.c.RevocationPolicyID, RevocationPolicyRevision: s.c.RevocationPolicyRevision}
	facts.Namespaces, facts.NamespaceCount = s.namespaceClosure()
	var retained ArtifactRetentionSlot
	if s.retention != nil {
		retained, err = s.retention.ReserveArtifact(call, request, facts)
		if retained != nil {
			defer retained.Close()
		}
		if err != nil || retained == nil {
			return 0, CBORFailure("issuance_retention")
		}
	}
	permit, err := s.c.Authority.BeginDirectIssue(call, request, facts)
	if permit != nil {
		defer permit.Close()
	}
	if err != nil || permit == nil {
		return 0, CBORFailure("issuance_authority")
	}
	guard := func() error {
		if e := s.check(call, window, parent); e != nil {
			return e
		}
		if e := permit.Check(call); e != nil {
			return CBORFailure("issuance_authority")
		}
		if retained != nil {
			if e := retained.Check(call); e != nil {
				return e
			}
		}
		return s.check(call, window, parent)
	}
	fields := []Field{
		{Name: "crypto_profile_id", Kind: TextString, Text: s.c.CryptoProfile}, {Name: "tenant_id", Kind: TextString, Text: s.c.Tenant}, {Name: "issuer_key_id", Kind: ByteString, Bytes: s.c.IssuerKeyID[:]}, {Name: "lease_id", Kind: ByteString, Bytes: lease[:]}, {Name: "session_nonce", Kind: ByteString, Bytes: nonce[:]}, {Name: "e2ee_psk", Kind: ByteString, Bytes: psk[:]}, {Name: "client_identity_digest", Kind: ByteString, Bytes: facts.ClientIdentity[:]}, {Name: "server_identity_digest", Kind: ByteString, Bytes: facts.ServerIdentity[:]}, {Name: "audience", Kind: TextString, Text: s.c.Audience},
		{Name: "candidates", Kind: EncodedArray, Bytes: s.candidates}, {Name: "session_contract", Kind: EncodedMap, Bytes: s.c.SessionContract}, {Name: "allowed_features", Number: s.c.AllowedFeatures}, {Name: "required_features", Number: s.c.RequiredFeatures}, {Name: "resume_policy", Kind: EncodedMap, Bytes: s.c.ResumePolicy}, {Name: "spend_policy", Kind: EncodedMap, Bytes: []byte{0xa1, 0, 0}},
		{Name: "issued_at_ms", Number: issued}, {Name: "initiation_not_after_ms", Number: parent.admissionEnd}, {Name: "session_not_after_ms", Number: scope.ExpiresMS}, {Name: "revocation_authority_id", Kind: TextString, Text: scope.Authority}, {Name: "revocation_authority_generation", Number: scope.Generation}, {Name: "revocation_epoch", Number: scope.Cohort}, {Name: "revocation_policy_id", Kind: TextString, Text: s.c.RevocationPolicyID}, {Name: "revocation_policy_revision", Number: s.c.RevocationPolicyRevision}, {Name: "namespace_capacity_digest", Kind: ByteString, Bytes: scope.CapacityDigest[:]},
	}
	for _, name := range []string{"artifact_version", "profile", "contract_revision"} {
		f, e := ConstantField("Artifact", name)
		if e != nil {
			return 0, e
		}
		fields = append(fields, f)
	}
	signed, err := s.codec.SignWith(fields, key, s.c.Signer, DecodeContext{}, guard)
	if err != nil {
		return 0, err
	}
	defer signed.Release()
	credential, err := signed.DetachCredential()
	if err != nil {
		return 0, err
	}
	if err = s.checkCredential(credential, s.c.Trust[0]); err != nil {
		return 0, err
	}
	if err = guard(); err != nil {
		return 0, err
	}
	if err = permit.Commit(call, credential.facts.Digest); err != nil {
		return 0, CBORFailure("issuance_commit")
	}
	if err = guard(); err != nil {
		return 0, err
	}
	wire, err := signed.Bytes()
	if err != nil {
		return 0, err
	}
	if retained != nil {
		if err = retained.Publish(call, wire); err != nil {
			return 0, err
		}
		if err = guard(); err != nil {
			return 0, err
		}
	}
	n = copy(dst, wire)
	if err = guard(); err != nil {
		clear(dst[:n])
		return 0, err
	}
	return n, nil
}

func (s *DirectIssuer) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancel()
	s.cancel = nil
	s.busy = false
	if s.closed {
		s.cleanupLocked()
	}
}

func (s *DirectIssuer) cleanupLocked() {
	if s.cleaned {
		return
	}
	s.cleaned = true
	clear(s.candidates)
	clear(s.authentication)
	s.candidates, s.authentication = nil, nil
	s.c = DirectIssuerConfig{}
	s.codec = nil
	s.certificates = [2]*Credential{}
	s.rules = nil
	s.tunnels.release()
	s.tunnels = nil
	s.retention = nil
	for _, ref := range s.trustRefs {
		ref.Release()
	}
	s.shared.Release()
	s.reservation.Release()
	close(s.done)
}

func (s *DirectIssuer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	if !s.busy {
		s.cleanupLocked()
	}
}

func (s *DirectIssuer) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*DirectIssuer) String() string   { return "DirectIssuer(<redacted>)" }
func (*DirectIssuer) GoString() string { return "DirectIssuer(<redacted>)" }

func (DirectIssueRequest) String() string   { return "DirectIssueRequest(<redacted>)" }
func (DirectIssueRequest) GoString() string { return "DirectIssueRequest(<redacted>)" }
func (DirectIssueRequest) MarshalJSON() ([]byte, error) {
	return []byte(`"DirectIssueRequest(<redacted>)"`), nil
}
