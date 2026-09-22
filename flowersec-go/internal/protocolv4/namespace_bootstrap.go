package protocolv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NamespaceBootstrap is the authenticated original online bootstrap pair.
// The caller must have verified the independent authority, nonce association
// and trust mapping. This local initializer does not fetch or authenticate a
// control-plane response and must not be called with an unauthenticated cache.
type NamespaceBootstrap struct {
	Rules *NamespaceRules
	Head  *NamespaceHead
	State []byte
}

// NamespaceAllocation names the two complete State backings and the shared
// live owner in that order. Accounts include the original tenant/Environment
// and any namespace subpool. Equal namespace names do not create a budget.
type NamespaceAllocation struct {
	Root     *resourcev4.Root
	Owners   [3]resourcev4.OwnerKey
	Accounts []resourcev4.Account
	// Additional includes the qualified allocator/provider/runtime costs for
	// each actual backing. Zero describes only the local implementation minimum.
	Additional [3]resourcev4.Vector
}

// NewBootstrappedNamespace admits the complete local online namespace at one
// gate before allocating either decoder. A decode/trust/clock/owner failure
// returns every unpublished allocation; success hands their original owners
// to the shared live namespace, retaining history through ordinary Close.
func NewBootstrappedNamespace(ctx context.Context, clock *timev4.Clock, trust NamespaceTrust, bootstrap NamespaceBootstrap, fetchDuration uint64, attemptLimit uint8, subscriberSlots uint32, allocation NamespaceAllocation) (_ *LiveNamespace, err error) {
	if ctx == nil || clock == nil || trust == nil || bootstrap.Rules == nil || bootstrap.Head == nil || bootstrap.Head.rules != bootstrap.Rules || uint64(len(bootstrap.State)) != bootstrap.Head.stateBytes || fetchDuration == 0 || attemptLimit == 0 {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	refs, err := reserveNamespace(bootstrap.Rules, subscriberSlots, allocation)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	return newBootstrappedNamespace(ctx, clock, trust, bootstrap, fetchDuration, attemptLimit, subscriberSlots, refs)
}

func reserveNamespace(rules *NamespaceRules, subscriberSlots uint32, allocation NamespaceAllocation) (refs [3]resourcev4.Reference, err error) {
	state, err := rules.StateCharge()
	if err != nil {
		return refs, err
	}
	live, err := rules.LiveNamespaceCharge(subscriberSlots)
	if err != nil {
		return refs, err
	}
	var requests [3]resourcev4.Request
	for i, owner := range allocation.Owners {
		if owner.Environment != allocation.Owners[0].Environment {
			return refs, resourcev4.ErrOwner
		}
		charge := state
		if i == 2 {
			charge = live
		}
		charge, err = charge.Add(allocation.Additional[i])
		if err != nil {
			return refs, err
		}
		requests[i] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: allocation.Accounts}
	}
	if err := allocation.Root.ReserveBatch(requests[:], refs[:]); err != nil {
		return refs, err
	}
	return refs, nil
}

func newBootstrappedNamespace(ctx context.Context, clock *timev4.Clock, trust NamespaceTrust, bootstrap NamespaceBootstrap, fetchDuration uint64, attemptLimit uint8, subscriberSlots uint32, refs [3]resourcev4.Reference) (_ *LiveNamespace, err error) {
	active, err := NewRevocationWorkspace(bootstrap.Rules, refs[0])
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = active.Close()
		}
	}()
	spare, err := NewRevocationWorkspace(bootstrap.Rules, refs[1])
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = spare.Close()
		}
	}()
	pair, err := active.Bind(bootstrap.Head, bootstrap.State)
	if err != nil {
		return nil, err
	}
	return NewLiveNamespace(ctx, clock, trust, pair, spare, fetchDuration, attemptLimit, subscriberSlots, refs[2])
}
