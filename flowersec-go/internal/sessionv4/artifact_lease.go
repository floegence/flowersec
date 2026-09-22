package sessionv4

import (
	"bytes"
	"context"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ArtifactLeaseConfig is a signature-verified material bundle plus independent
// original issuer/activation trust. It has no local private key or callback
// that claims durable consumption. The SQLite ledger remains the once authority.
type ArtifactLeaseConfig struct {
	Artifact, Proof, ClientCertificate, ServerCertificate *protocolv4.SignedMap
	Source                                                string
	Verification                                          LiveProofVerification
	Validation                                            [3]protocolv4.CredentialValidation
	MapBytes, MapNodes                                    int
	RuntimeBytes                                          uint64
}

// ArtifactLease owns original canonical credentials independently of local
// identity handles. Multiple material wrappers still share its one local claim
// and the same durable tenant/issuer/lease key. Local claim failure is not a
// durable spent assertion, and Close never changes a durable ledger.
type ArtifactLease struct {
	mu                       sync.Mutex
	maps                     [4]*protocolv4.SignedMap
	codecs                   [4]*protocolv4.SignedMapCodec
	credentials              [3]*protocolv4.Credential
	validation               [3]protocolv4.CredentialValidation
	verification             LiveProofVerification
	selection                *protocolv4.PoolSelectionWorkspace
	session                  protocolv4.ArtifactSessionParameters
	reservation, shared      resourcev4.Reference
	source                   string
	uses                     uint32
	preparing                *ConnectionMaterial
	claimed, closed, cleaned bool
	done                     chan struct{}
}

func (*ArtifactLease) String() string               { return "Flowersec.ArtifactLease" }
func (*ArtifactLease) GoString() string             { return "Flowersec.ArtifactLease" }
func (*ArtifactLease) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var leaseSchemas = [...]string{"Artifact", "ActivationAuthorization", "IdentityCertificate", "IdentityCertificate"}

func ArtifactLeaseCharge(mapBytes, nodes int, runtimeBytes uint64) (resourcev4.Vector, error) {
	if mapBytes < 1024 || mapBytes > 1<<20 || nodes <= 0 || nodes > 1<<20 || runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ArtifactLease{})), resourcev4.Items: 1}
	add := func(n uint64) error {
		var err error
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: n})
		return err
	}
	for index, schema := range leaseSchemas {
		limit, err := protocolv4.SchemaByteLimit(schema)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		n, err := protocolv4.SignedMapBackingBytes(schema, min(limit, mapBytes), nodes)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if err = add(n); err != nil {
			return resourcev4.Vector{}, err
		}
		if index != 1 {
			n, err = protocolv4.CredentialBackingBytes(schema)
			if err != nil {
				return resourcev4.Vector{}, err
			}
			if err = add(n); err != nil {
				return resourcev4.Vector{}, err
			}
		}
	}
	for _, cost := range []func() (uint64, error){protocolv4.ActivationAuthorityBackingBytes, protocolv4.ActivationBindingBackingBytes, func() (uint64, error) { return protocolv4.PoolSelectionBackingBytes(mapBytes, mapBytes) }} {
		n, err := cost()
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if err = add(n); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	for _, schema := range []string{"ConnectionActivationDelegation", "OnceAuthorityRef"} {
		n, err := protocolv4.SchemaByteLimit(schema)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if err = add(uint64(n)); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	if err := add(runtimeBytes); err != nil {
		return resourcev4.Vector{}, err
	}
	return charge, nil
}

// ArtifactLeaseBytesConfig fixes the source profile and independent trust for
// the Artifact and the two complete certificates. ActivationSigningKeyID is
// the original source's selected independent delegation, never a fallback key.
type ArtifactLeaseBytesConfig struct {
	Artifact, Proof, ClientCertificate, ServerCertificate []byte
	Source, ActivationSigningKeyID                        string
	Trust                                                 [3]*protocolv4.NamespaceTrustStore
	MapBytes, MapNodes                                    int
	RuntimeBytes                                          uint64
}

func NewArtifactLeaseFromBytes(c ArtifactLeaseBytesConfig, reservation, dependencies resourcev4.Reference) (*ArtifactLease, error) {
	for _, trust := range c.Trust {
		if trust == nil {
			return nil, cryptov4.ErrConfiguration
		}
	}
	if c.ActivationSigningKeyID == "" {
		return nil, cryptov4.ErrConfiguration
	}
	config := ArtifactLeaseConfig{Source: c.Source, MapBytes: c.MapBytes, MapNodes: c.MapNodes, RuntimeBytes: c.RuntimeBytes}
	return newArtifactLease(config, [4][]byte{c.Artifact, c.Proof, c.ClientCertificate, c.ServerCertificate}, &c, reservation, dependencies)
}

func NewArtifactLease(c ArtifactLeaseConfig, reservation, dependencies resourcev4.Reference) (*ArtifactLease, error) {
	if c.Artifact == nil || c.ClientCertificate == nil || c.ServerCertificate == nil || c.Verification.Rules == nil || c.Verification.Key == ([32]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	for _, part := range []struct {
		schema string
		wire   []byte
	}{{"ConnectionActivationDelegation", c.Verification.Delegation}, {"OnceAuthorityRef", c.Verification.Once}} {
		limit, err := protocolv4.SchemaByteLimit(part.schema)
		if err != nil || len(part.wire) == 0 || len(part.wire) > limit {
			return nil, cryptov4.ErrConfiguration
		}
	}
	var wire [4][]byte
	for i, original := range []*protocolv4.SignedMap{c.Artifact, c.Proof, c.ClientCertificate, c.ServerCertificate} {
		if original == nil {
			continue
		}
		var err error
		wire[i], err = original.Bytes()
		if err != nil {
			return nil, err
		}
	}
	return newArtifactLease(c, wire, nil, reservation, dependencies)
}

func newArtifactLease(c ArtifactLeaseConfig, wire [4][]byte, trusted *ArtifactLeaseBytesConfig, reservation, dependencies resourcev4.Reference) (_ *ArtifactLease, err error) {
	if len(wire[0]) == 0 || len(wire[2]) == 0 || len(wire[3]) == 0 || reservation == dependencies ||
		c.Source != "preauthorized_pool" && c.Source != "live_authority" || (c.Source == "preauthorized_pool") != (len(wire[1]) != 0) {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ArtifactLeaseCharge(c.MapBytes, c.MapNodes, c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	l := &ArtifactLease{source: c.Source, reservation: owned, shared: shared, validation: c.Validation, verification: c.Verification, done: make(chan struct{})}
	l.verification.Delegation, l.verification.Once = bytes.Clone(c.Verification.Delegation), bytes.Clone(c.Verification.Once)
	adopted := false
	defer func() {
		if !adopted {
			l.Close()
		}
	}()
	for index, schema := range leaseSchemas {
		limit, e := protocolv4.SchemaByteLimit(schema)
		if e != nil {
			return nil, e
		}
		l.codecs[index], err = protocolv4.NewSignedMapCodec(schema, min(limit, c.MapBytes), c.MapNodes)
		if err != nil {
			return nil, err
		}
	}
	originals := [...]*protocolv4.SignedMap{c.Artifact, c.ClientCertificate, c.ServerCertificate}
	for credentialIndex, mapIndex := range []int{0, 2, 3} {
		if trusted != nil {
			l.maps[mapIndex], err = l.codecs[mapIndex].VerifyCredential(wire[mapIndex], trusted.Trust[credentialIndex])
		} else {
			l.maps[mapIndex], err = l.codecs[mapIndex].Verify(wire[mapIndex], originals[credentialIndex].Key(), protocolv4.DecodeContext{})
		}
		if err != nil {
			return nil, err
		}
		l.credentials[credentialIndex], err = l.maps[mapIndex].DetachCredential()
		if err != nil {
			return nil, err
		}
		if trusted != nil {
			l.validation[credentialIndex], err = trusted.Trust[credentialIndex].ResolveCredential(l.credentials[credentialIndex])
			if err != nil {
				return nil, err
			}
		}
	}
	if trusted != nil {
		delegationLimit, e := protocolv4.SchemaByteLimit("ConnectionActivationDelegation")
		if e != nil {
			return nil, e
		}
		onceLimit, e := protocolv4.SchemaByteLimit("OnceAuthorityRef")
		if e != nil {
			return nil, e
		}
		resolved, e := trusted.Trust[0].ResolveActivation(l.credentials[0], trusted.ActivationSigningKeyID, make([]byte, delegationLimit), make([]byte, onceLimit))
		if e != nil {
			return nil, e
		}
		l.verification = LiveProofVerification{Rules: resolved.Rules, Key: resolved.Key, Delegation: resolved.Delegation, Once: resolved.Once}
	}
	if len(wire[1]) != 0 {
		l.maps[1], err = l.codecs[1].Verify(wire[1], l.verification.Key, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": c.Source}})
		if err != nil {
			return nil, err
		}
	}
	l.session, err = l.maps[0].SessionParameters()
	if err != nil {
		return nil, err
	}

	parent := l.credentials[0].Scope()
	for role, name := range []string{"client_identity_digest", "server_identity_digest"} {
		cert := l.credentials[role+1]
		scope := cert.Scope()
		digest, ok := l.maps[0].Field(name).ByteString()
		facts := cert.Facts()
		if !ok || !bytes.Equal(digest, facts.Digest[:]) {
			return nil, cryptov4.ErrConfiguration
		}
		if scope.Schema != "IdentityCertificate" || scope.Role != uint64(role) || scope.Tenant != parent.Tenant || scope.Audience != parent.Audience || scope.Profile != parent.Profile {
			return nil, cryptov4.ErrConfiguration
		}
	}
	l.selection, err = protocolv4.NewPoolSelectionWorkspace(c.MapBytes, c.MapBytes)
	if err != nil {
		return nil, err
	}
	if err = l.check(); err != nil {
		return nil, err
	}
	if c.Source == "preauthorized_pool" {
		index, ok := l.maps[1].Field("candidate_selection").Named("PoolSelectionRef", "candidate_indices").Index(0).Uint()
		if !ok {
			return nil, cryptov4.ErrConfiguration
		}
		if _, _, err = l.activation(index); err != nil {
			return nil, err
		}
	}
	adopted = true
	return l, nil
}

// check runs with a material/constructor pin, never under the lease mutex.
func (l *ArtifactLease) check() error {
	return l.checkForUse(false)
}

func (l *ArtifactLease) checkForUse(issuing bool) error {
	if err := l.reservation.Check(); err != nil {
		return err
	}
	if err := l.shared.Check(); err != nil {
		return err
	}
	for index, c := range l.credentials {
		if _, err := l.validation[index].CheckMaterialCredential(c, l.session.SessionNotAfterMS, l.reservation); err != nil {
			return err
		}
	}
	if l.source == "live_authority" {
		check := l.validation[0].CheckLiveActivationConfiguration
		if issuing {
			check = l.validation[0].CheckLiveActivationSource
		}
		return check(l.verification.Rules, l.credentials[0], l.verification.Delegation, l.verification.Once, l.verification.Key, l.reservation)
	}
	return nil
}

func (l *ArtifactLease) activation(index uint64) (*protocolv4.ActivationBinding, *protocolv4.ActivationAuthority, error) {
	b, err := l.selection.BindActivation(l.maps[0], l.maps[1], l.source, index)
	if err != nil {
		return nil, nil, err
	}
	a, err := l.verification.Rules.BindActivationAuthority(b, l.maps[0], l.verification.Delegation, l.verification.Once)
	if err != nil {
		return nil, nil, err
	}
	stale, lifetime := uint64(math.MaxUint64), uint64(math.MaxUint64)
	for _, v := range l.validation {
		requirement := v.Policy.Requirements()
		stale = min(stale, requirement.StalenessMS)
		lifetime = min(lifetime, requirement.SignerLifetimeMS)
	}
	_, err = l.validation[0].Namespace.CheckDetachedActivation(a, l.credentials[0], l.validation[0].Issuer, stale, lifetime, l.session.SessionNotAfterMS)
	return b, a, err
}

type artifactLeaseUse struct {
	lease *ArtifactLease
	ref   resourcev4.Reference
}

func (l *ArtifactLease) capture(environment resourcev4.Reference) (artifactLeaseUse, error) {
	if l == nil {
		return artifactLeaseUse{}, cryptov4.ErrConfiguration
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.claimed || l.preparing != nil {
		return artifactLeaseUse{}, cryptov4.ErrClosed
	}
	if l.uses == math.MaxUint32 {
		return artifactLeaseUse{}, cryptov4.ErrCapacity
	}
	if err := l.reservation.CheckSameEnvironment(environment); err != nil {
		return artifactLeaseUse{}, err
	}
	ref, err := l.reservation.Borrow()
	if err != nil {
		return artifactLeaseUse{}, err
	}
	l.uses++
	return artifactLeaseUse{l, ref}, nil
}

func (u *artifactLeaseUse) release() {
	if u.lease == nil {
		return
	}
	l := u.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	u.ref.Release()
	*u = artifactLeaseUse{}
	l.uses--
	l.cleanupLocked()
}

func (l *ArtifactLease) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.cleanupLocked()
}

func (l *ArtifactLease) cleanupLocked() {
	if !l.closed || l.cleaned || l.uses != 0 {
		return
	}
	for _, m := range l.maps {
		if m != nil {
			m.Release()
		}
	}
	clear(l.verification.Delegation)
	clear(l.verification.Once)
	l.maps, l.codecs, l.credentials = [4]*protocolv4.SignedMap{}, [4]*protocolv4.SignedMapCodec{}, [3]*protocolv4.Credential{}
	l.verification = LiveProofVerification{}
	l.validation = [3]protocolv4.CredentialValidation{}
	l.selection = nil
	l.shared.Release()
	l.reservation.Release()
	l.shared, l.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	l.cleaned = true
	close(l.done)
}

func (l *ArtifactLease) WaitCleanup(ctx context.Context) error {
	if l == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
