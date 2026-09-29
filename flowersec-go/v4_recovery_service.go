package flowersec

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// V4RecoveryMACKey holds an independently provisioned application recovery
// key. No Session, traffic secret or transport identity can construct it.
type V4RecoveryMACKey struct{ inner *cryptov4.RecoveryMACKey }

func V4RecoveryMACKeyCharge() V4ResourceVector {
	charge := cryptov4.RecoveryMACKeyCharge()
	charge[V4SDKBytes] += uint64(unsafe.Sizeof(V4RecoveryMACKey{}))
	return charge
}

func ImportV4RecoveryMACKey(material [32]byte, reservation V4ResourceReference) (*V4RecoveryMACKey, error) {
	defer clear(material[:])
	owned, err := reservation.Take(V4RecoveryMACKeyCharge())
	if err != nil {
		return nil, err
	}
	inner, err := cryptov4.ImportRecoveryMACKey(material, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &V4RecoveryMACKey{inner: inner}, nil
}

func (k *V4RecoveryMACKey) Close() {
	if k != nil && k.inner != nil {
		k.inner.Close()
	}
}
func (*V4RecoveryMACKey) String() string               { return "Flowersec.RecoveryMACKey" }
func (*V4RecoveryMACKey) GoString() string             { return "Flowersec.RecoveryMACKey" }
func (*V4RecoveryMACKey) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type V4RecoveryKey struct {
	ID            [16]byte
	Protection    uint8
	Public        [32]byte
	MAC           *V4RecoveryMACKey
	Signer        V4MapSigner
	SignerBacking V4ResourceReference
}

// V4RecoveryVerifierConfig freezes at most sixteen independently trusted keys
// for one logical business service. Tokens can select only this captured set.
type V4RecoveryVerifierConfig struct {
	Service      V4ExecutionService
	Clock        *V4Clock
	Keys         []V4RecoveryKey
	RuntimeBytes uint64
}

// V4RecoveryVerifier attaches only through the original service registry.
// Target capture, request authentication and atomic token consumption remain
// on the accepted Stream's original SDK dispatch and durable transaction.
type V4RecoveryVerifier struct{ inner *rpcv4.RecoveryVerifier }

func (c V4RecoveryVerifierConfig) internal(keys *[16]rpcv4.RecoveryKey) (rpcv4.RecoveryVerifierConfig, error) {
	if len(c.Keys) == 0 || len(c.Keys) > len(keys) {
		return rpcv4.RecoveryVerifierConfig{}, cryptov4.ErrConfiguration
	}
	for i, key := range c.Keys {
		keys[i] = rpcv4.RecoveryKey{ID: key.ID, Protection: key.Protection, Public: key.Public, Signer: key.Signer, SignerBacking: key.SignerBacking}
		if key.MAC != nil {
			if key.MAC.inner == nil {
				return rpcv4.RecoveryVerifierConfig{}, cryptov4.ErrConfiguration
			}
			keys[i].MAC = key.MAC.inner
		}
	}
	return rpcv4.RecoveryVerifierConfig{Service: c.Service, Clock: c.Clock, Keys: keys[:len(c.Keys)], RuntimeBytes: c.RuntimeBytes}, nil
}

func V4RecoveryVerifierCharge(config V4RecoveryVerifierConfig) (V4ResourceVector, error) {
	var keys [16]rpcv4.RecoveryKey
	inner, err := config.internal(&keys)
	if err != nil {
		return V4ResourceVector{}, err
	}
	charge, err := rpcv4.RecoveryVerifierCharge(inner)
	if err != nil {
		return V4ResourceVector{}, err
	}
	return charge.Add(V4ResourceVector{V4SDKBytes: uint64(unsafe.Sizeof(V4RecoveryVerifier{}))})
}

func NewV4RecoveryVerifier(config V4RecoveryVerifierConfig, reservation V4ResourceReference) (*V4RecoveryVerifier, error) {
	charge, err := V4RecoveryVerifierCharge(config)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	var keys [16]rpcv4.RecoveryKey
	innerConfig, err := config.internal(&keys)
	if err != nil {
		owned.Release()
		return nil, err
	}
	inner, err := rpcv4.NewRecoveryVerifier(innerConfig, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &V4RecoveryVerifier{inner: inner}, nil
}

func (v *V4RecoveryVerifier) Close() {
	if v != nil && v.inner != nil {
		v.inner.Close()
	}
}
func (*V4RecoveryVerifier) String() string               { return "Flowersec.RecoveryVerifier" }
func (*V4RecoveryVerifier) GoString() string             { return "Flowersec.RecoveryVerifier" }
func (*V4RecoveryVerifier) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type V4ResumeStreamBinding = sessionv4.ResumeStreamBinding
type V4CheckpointIssuanceOptions = sessionv4.CheckpointIssuanceOptions

// NewV4ResumeRegistration selects the SDK recovery exchange in the existing
// unary registration table. The matching raw kind registration supplies the
// post-recovery handler; it is entered only after accepted durable progress.
func NewV4ResumeRegistration(method uint32, namespace string, typeID uint32) V4UnaryRegistration {
	return sessionv4.UnaryRegistration{Resume: true, Method: method, Namespace: namespace, Type: typeID, WorkClass: sessionv4.ApplicationShort}
}
