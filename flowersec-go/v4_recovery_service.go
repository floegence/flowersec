package flowersec

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// RecoveryMACKey holds an independently provisioned application recovery
// key. No Session, traffic secret or transport identity can construct it.
type RecoveryMACKey struct{ inner *cryptov4.RecoveryMACKey }

func RecoveryMACKeyCharge() ResourceVector {
	charge := cryptov4.RecoveryMACKeyCharge()
	charge[SDKBytes] += uint64(unsafe.Sizeof(RecoveryMACKey{}))
	return charge
}

func ImportRecoveryMACKey(material [32]byte, reservation ResourceReference) (*RecoveryMACKey, error) {
	defer clear(material[:])
	owned, err := reservation.Take(RecoveryMACKeyCharge())
	if err != nil {
		return nil, err
	}
	inner, err := cryptov4.ImportRecoveryMACKey(material, owned)
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &RecoveryMACKey{inner: inner}, nil
}

func (k *RecoveryMACKey) Close() {
	if k != nil && k.inner != nil {
		k.inner.Close()
	}
}
func (*RecoveryMACKey) String() string               { return "Flowersec.RecoveryMACKey" }
func (*RecoveryMACKey) GoString() string             { return "Flowersec.RecoveryMACKey" }
func (*RecoveryMACKey) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type RecoveryKey struct {
	ID            [16]byte
	Protection    uint8
	Public        [32]byte
	MAC           *RecoveryMACKey
	Signer        MapSigner
	SignerBacking ResourceReference
}

// RecoveryVerifierConfig freezes at most sixteen independently trusted keys
// for one logical business service. Tokens can select only this captured set.
type RecoveryVerifierConfig struct {
	Service      ExecutionService
	Clock        *Clock
	Keys         []RecoveryKey
	RuntimeBytes uint64
}

// RecoveryVerifier attaches only through the original service registry.
// Target capture, request authentication and atomic token consumption remain
// on the accepted Stream's original SDK dispatch and durable transaction.
type RecoveryVerifier struct{ inner *rpcv4.RecoveryVerifier }

func (c RecoveryVerifierConfig) internal(keys *[16]rpcv4.RecoveryKey) (rpcv4.RecoveryVerifierConfig, error) {
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

func RecoveryVerifierCharge(config RecoveryVerifierConfig) (ResourceVector, error) {
	var keys [16]rpcv4.RecoveryKey
	inner, err := config.internal(&keys)
	if err != nil {
		return ResourceVector{}, err
	}
	charge, err := rpcv4.RecoveryVerifierCharge(inner)
	if err != nil {
		return ResourceVector{}, err
	}
	return charge.Add(ResourceVector{SDKBytes: uint64(unsafe.Sizeof(RecoveryVerifier{}))})
}

func NewRecoveryVerifier(config RecoveryVerifierConfig, reservation ResourceReference) (*RecoveryVerifier, error) {
	charge, err := RecoveryVerifierCharge(config)
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
	return &RecoveryVerifier{inner: inner}, nil
}

func (v *RecoveryVerifier) Close() {
	if v != nil && v.inner != nil {
		v.inner.Close()
	}
}
func (*RecoveryVerifier) String() string               { return "Flowersec.RecoveryVerifier" }
func (*RecoveryVerifier) GoString() string             { return "Flowersec.RecoveryVerifier" }
func (*RecoveryVerifier) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type ResumeStreamBinding = sessionv4.ResumeStreamBinding
type CheckpointIssuanceOptions = sessionv4.CheckpointIssuanceOptions

// NewResumeRegistration selects the SDK recovery exchange in the existing
// unary registration table. The matching raw kind registration supplies the
// post-recovery handler; it is entered only after accepted durable progress.
func NewResumeRegistration(method uint32, namespace string, typeID uint32) UnaryRegistration {
	return sessionv4.UnaryRegistration{Resume: true, Method: method, Namespace: namespace, Type: typeID, WorkClass: sessionv4.ApplicationShort}
}
