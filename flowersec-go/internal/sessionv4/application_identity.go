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

// ApplicationIdentityConfig captures one complete immutable certificate and
// its exact non-exporting local key capabilities. Dependencies owns the actual
// key-provider/trust references; no provider is closed by this borrower.
type ApplicationIdentityConfig struct {
	Certificate  *protocolv4.SignedMap
	Signer       cryptov4.IdentitySigner
	StaticDH     cryptov4.StaticDH
	Validation   protocolv4.CredentialValidation
	Role         protocolv4.Direction
	MapNodes     int
	RuntimeBytes uint64
}

// ApplicationIdentity stops advertising on Close, while already captured
// material keeps the same certificate and keys until its real last use exits.
// Rotation never changes an existing identity or reads a current-key getter.
type ApplicationIdentity struct {
	mu                  sync.Mutex
	certificate         *protocolv4.SignedMap
	credential          *protocolv4.Credential
	codec               *protocolv4.SignedMapCodec
	signer              cryptov4.IdentitySigner
	dh                  cryptov4.StaticDH
	validation          protocolv4.CredentialValidation
	reservation, shared resourcev4.Reference
	role                protocolv4.Direction
	uses                uint32
	closed, cleaned     bool
	done                chan struct{}
}

func (*ApplicationIdentity) String() string               { return "Flowersec.ApplicationIdentity" }
func (*ApplicationIdentity) GoString() string             { return "Flowersec.ApplicationIdentity" }
func (*ApplicationIdentity) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func ApplicationIdentityCharge(nodes int, runtimeBytes uint64) (resourcev4.Vector, error) {
	if nodes <= 0 || nodes > 1<<20 || runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	limit, err := protocolv4.SchemaByteLimit("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("IdentityCertificate", limit, nodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	credential, err := protocolv4.CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ApplicationIdentity{})), resourcev4.Items: 1}
	for _, n := range []uint64{codec, credential, runtimeBytes} {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: n})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}

// ApplicationIdentityBytesConfig fixes an independent trust owner before any
// credential is decoded. Certificate bytes cannot select a trust root.
type ApplicationIdentityBytesConfig struct {
	Certificate  []byte
	Trust        *protocolv4.NamespaceTrustStore
	Signer       cryptov4.IdentitySigner
	StaticDH     cryptov4.StaticDH
	Role         protocolv4.Direction
	MapNodes     int
	RuntimeBytes uint64
}

func NewApplicationIdentityFromBytes(c ApplicationIdentityBytesConfig, reservation, dependencies resourcev4.Reference) (*ApplicationIdentity, error) {
	if c.Trust == nil || len(c.Certificate) == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	config := ApplicationIdentityConfig{Signer: c.Signer, StaticDH: c.StaticDH, Role: c.Role, MapNodes: c.MapNodes, RuntimeBytes: c.RuntimeBytes}
	return newApplicationIdentity(config, c.Certificate, c.Trust, reservation, dependencies)
}

func NewApplicationIdentity(c ApplicationIdentityConfig, reservation, dependencies resourcev4.Reference) (*ApplicationIdentity, error) {
	if c.Certificate == nil {
		return nil, cryptov4.ErrConfiguration
	}
	wire, err := c.Certificate.Bytes()
	if err != nil {
		return nil, err
	}
	return newApplicationIdentity(c, wire, nil, reservation, dependencies)
}

func newApplicationIdentity(c ApplicationIdentityConfig, wire []byte, trust *protocolv4.NamespaceTrustStore, reservation, dependencies resourcev4.Reference) (_ *ApplicationIdentity, err error) {
	if c.Signer == nil || c.StaticDH == nil || c.Role > protocolv4.ServerToClient || reservation == dependencies {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ApplicationIdentityCharge(c.MapNodes, c.RuntimeBytes)
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
	i := &ApplicationIdentity{reservation: owned, shared: shared, signer: c.Signer, dh: c.StaticDH, validation: c.Validation, role: c.Role, done: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			i.Close()
		}
	}()
	limit, err := protocolv4.SchemaByteLimit("IdentityCertificate")
	if err != nil {
		return nil, err
	}
	i.codec, err = protocolv4.NewSignedMapCodec("IdentityCertificate", limit, c.MapNodes)
	if err != nil {
		return nil, err
	}
	if trust != nil {
		i.certificate, err = i.codec.VerifyCredential(wire, trust)
	} else {
		i.certificate, err = i.codec.Verify(wire, c.Certificate.Key(), protocolv4.DecodeContext{})
	}
	if err != nil {
		return nil, err
	}
	i.credential, err = i.certificate.DetachCredential()
	if err != nil {
		return nil, err
	}
	if trust != nil {
		i.validation, err = trust.ResolveCredential(i.credential)
		if err != nil {
			return nil, err
		}
	}
	if i.credential.Scope().Role != uint64(c.Role) {
		return nil, cryptov4.ErrConfiguration
	}
	if err = i.check(); err != nil {
		return nil, err
	}
	adopted = true
	return i, nil
}

// check requires the constructor's position or an existing identityUse pin.
// Key-provider and trust calls run outside the identity's ownership lock.
func (i *ApplicationIdentity) check() error {
	if err := i.reservation.Check(); err != nil {
		return err
	}
	if err := i.shared.Check(); err != nil {
		return err
	}
	ed, ok := i.certificate.Field("ed25519_public_key").ByteString()
	dh, dhOK := i.certificate.Field("noise_static_public_key").Named("NoiseStaticPublicKey", "public_key_bytes").ByteString()
	if !ok || !dhOK || !bytes.Equal(ed, i.signer.PublicKey()) || !bytes.Equal(dh, i.dh.PublicKey()) {
		return cryptov4.ErrConfiguration
	}
	// Public-key capability calls may have real provider tails. Recheck current
	// authority after those calls before returning a newly usable identity.
	_, err := i.validation.CheckMaterialCredential(i.credential, i.credential.Scope().ExpiresMS, i.reservation)
	return err
}

// identityUse is stored in the material's charged metadata. It has one physical
// release, regardless of how many opaque material/lease handles are copied.
type identityUse struct {
	identity *ApplicationIdentity
	ref      resourcev4.Reference
}

func (i *ApplicationIdentity) capture(environment resourcev4.Reference) (identityUse, error) {
	if i == nil {
		return identityUse{}, cryptov4.ErrConfiguration
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return identityUse{}, cryptov4.ErrClosed
	}
	if i.uses == math.MaxUint32 {
		return identityUse{}, cryptov4.ErrCapacity
	}
	if err := i.reservation.CheckSameEnvironment(environment); err != nil {
		return identityUse{}, err
	}
	ref, err := i.reservation.Borrow()
	if err != nil {
		return identityUse{}, err
	}
	i.uses++
	return identityUse{i, ref}, nil
}

func (u *identityUse) release() {
	if u.identity == nil {
		return
	}
	i := u.identity
	i.mu.Lock()
	defer i.mu.Unlock()
	u.ref.Release()
	*u = identityUse{}
	i.uses--
	i.cleanupLocked()
}

func (i *ApplicationIdentity) Close() {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	i.cleanupLocked()
}

func (i *ApplicationIdentity) cleanupLocked() {
	if !i.closed || i.cleaned || i.uses != 0 {
		return
	}
	if i.certificate != nil {
		i.certificate.Release()
	}
	i.certificate, i.credential, i.codec = nil, nil, nil
	i.signer, i.dh = nil, nil
	i.validation = protocolv4.CredentialValidation{}
	i.shared.Release()
	i.reservation.Release()
	i.shared, i.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	i.cleaned = true
	close(i.done)
}

func (i *ApplicationIdentity) WaitCleanup(ctx context.Context) error {
	if i == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-i.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
