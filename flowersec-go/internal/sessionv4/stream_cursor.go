package sessionv4

import (
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ReaderCursorOptions fixes the original target before any receive advancement.
// An empty delimiter selects Exact, including exact(0). MaxBytes is the fixed
// until target; it is not a second read limit or a caller-supplied budget.
type ReaderCursorOptions struct {
	Exact     uint64
	Delimiter []byte
	MaxBytes  uint64
}

// ReaderCursor admits the cursor and its independent delivery authorization
// against this Stream's actual root and scopes. Neither caller-created
// references nor an unrelated endpoint can authorize the private result.
func (o *StreamOwnership) ReaderCursor(options ReaderCursorOptions) (_ *ReaderCursor, err error) {
	if o == nil {
		return nil, cursorConstructionError(ErrStreamOwned)
	}
	var target cursorTarget
	if len(options.Delimiter) == 0 {
		if options.MaxBytes != 0 {
			return nil, cursorConstructionError(ErrCursorTarget)
		}
		target, err = exactCursorTarget(options.Exact, options.Exact)
	} else {
		if options.Exact != 0 {
			return nil, cursorConstructionError(ErrCursorTarget)
		}
		target, err = untilCursorTarget(options.Delimiter, options.MaxBytes, options.MaxBytes)
	}
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	a, _, flow, _, err := o.begin()
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	defer o.end()
	o.mu.Lock()
	if o.allocationRoot == nil || o.allocationRuntimeBytes == 0 || o.cursorSerial == math.MaxUint64 {
		o.mu.Unlock()
		return nil, cursorConstructionError(cryptov4.ErrConfiguration)
	}
	o.cursorSerial++
	serial, root, key, runtimeBytes := o.cursorSerial, o.allocationRoot, o.allocationOwner, o.allocationRuntimeBytes
	accounts := o.allocationScopes
	count := o.allocationCount
	o.mu.Unlock()
	charge, err := ReaderCursorCharge(target.limit)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	verification, err := protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	var requests [2]resourcev4.Request
	for i, cost := range [2]resourcev4.Vector{charge, verification} {
		var identity [33]byte
		copy(identity[:8], "cursor4/")
		copy(identity[8:24], key.Backing[:])
		binary.BigEndian.PutUint64(identity[24:32], serial)
		identity[32] = byte(i)
		digest := sha256.Sum256(identity[:])
		owner := key
		copy(owner.Backing[:], digest[:16])
		requests[i] = resourcev4.Request{Owner: owner, Charge: cost, Accounts: accounts[:count], ResultOwner: i == 0}
	}
	var refs [2]resourcev4.Reference
	if err = root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, cursorConstructionError(err)
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	authorization, err := a.engine.ForkApplicationDelivery(refs[1])
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	defer func() {
		if err != nil {
			authorization.Close(err)
		}
	}()
	return admitOwnedReaderCursor(flow.receive, target, refs[0], authorization, o)
}
