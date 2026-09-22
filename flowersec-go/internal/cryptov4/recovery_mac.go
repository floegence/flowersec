package cryptov4

import (
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// RecoveryMACKey is an independently provisioned application recovery key.
// There is deliberately no constructor from an Engine, Session or traffic
// secret. Only the registered resume-token domain may reach its MAC capability.
type RecoveryMACKey struct {
	mu          sync.Mutex
	key         [32]byte
	reservation resourcev4.Reference
	closed      bool
}

func RecoveryMACKeyCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RecoveryMACKey{})) + 1024, resourcev4.Items: 1, resourcev4.WorkSlots: 1}
}

// ImportRecoveryMACKey copies one application key into its already admitted
// owner. The caller remains responsible for its original provisioned material.
func ImportRecoveryMACKey(material [32]byte, reservation resourcev4.Reference) (*RecoveryMACKey, error) {
	defer clear(material[:])
	owned, err := reservation.Take(RecoveryMACKeyCharge())
	if err != nil {
		return nil, err
	}
	return &RecoveryMACKey{key: material, reservation: owned}, nil
}

func (k *RecoveryMACKey) ResumeMAC(input []byte) ([32]byte, error) {
	var out [32]byte
	if k == nil {
		return out, ErrConfiguration
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return out, ErrClosed
	}
	if err := k.reservation.Check(); err != nil {
		return out, err
	}
	// The fixed codec supplies the exact registry projection. A key capability
	// is not an arbitrary HMAC oracle or a way to authenticate transport records.
	if err := protocolv4.ValidateResumeMACInput(input); err != nil {
		return out, err
	}
	h := hmac.New(sha256.New, k.key[:])
	_, _ = h.Write(input)
	h.Sum(out[:0])
	return out, nil
}

func (k *RecoveryMACKey) Borrow(backing resourcev4.Reference) (resourcev4.Reference, error) {
	if k == nil {
		return resourcev4.Reference{}, ErrConfiguration
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return resourcev4.Reference{}, ErrClosed
	}
	if err := k.reservation.CheckSameEnvironment(backing); err != nil {
		return resourcev4.Reference{}, err
	}
	return k.reservation.Borrow()
}
func (k *RecoveryMACKey) Close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	k.closed = true
	clear(k.key[:])
	k.reservation.Seal()
	k.reservation.Release()
	k.reservation = resourcev4.Reference{}
}
func (*RecoveryMACKey) String() string               { return "Flowersec.RecoveryMACKey" }
func (*RecoveryMACKey) GoString() string             { return "Flowersec.RecoveryMACKey" }
func (*RecoveryMACKey) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
