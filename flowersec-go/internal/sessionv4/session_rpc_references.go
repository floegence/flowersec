package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// rpcServicesReferences holds the concrete constructor aliases of the original
// aggregate. Each position has one fixed recipient; it cannot fund unrelated
// borrows. Controller admission obtains them before source Acquire.
type rpcServicesReferences struct {
	plan                   *SessionPlan
	registry               *rpcv4.ServiceRegistry
	shortExecution         resourcev4.Reference
	callerResult           resourcev4.Reference
	callerOwner            [3]resourcev4.Reference
	callerAuthority        resourcev4.Reference
	dispatch, notification resourcev4.Reference
	registryBorrows        [3]resourcev4.Reference
	registryNeeded         [3]bool
}

func (b *rpcServicesBatch) reserveQueries() error {
	if b.queries != nil {
		return b.queries.checkPreparation(b.plan)
	}
	p := b.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.rpcPreparing {
		return cryptov4.ErrTransition
	}
	var err error
	b.queries, err = p.reserveContractQueriesLocked()
	return err
}

func (b *rpcServicesBatch) reserveReferences(refs []resourcev4.Reference) (err error) {
	if b.references.plan != nil {
		return b.references.check(b)
	}
	if !b.prepared || b.used || len(refs) != b.count {
		return resourcev4.ErrOwner
	}
	p, c := b.plan, b.config
	r := &b.references
	r.plan, r.registry = p, c.ExecutionRegistry
	r.registryNeeded = rpcRegistryReferences(c)
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	for _, pair := range []struct {
		target *resourcev4.Reference
		source resourcev4.Reference
	}{
		{&r.shortExecution, refs[rpcServicesShortCalls]},
		{&r.callerResult, refs[rpcServicesCallerResult]},
		{&r.callerOwner[0], refs[rpcServicesCallerOwner]},
		{&r.callerOwner[1], refs[rpcServicesCallerOwner]},
		{&r.callerOwner[2], refs[rpcServicesCallerOwner]},
		{&r.callerAuthority, refs[rpcServicesCallerAuthority]},
	} {
		*pair.target, err = pair.source.Borrow()
		if err != nil {
			return err
		}
	}
	p.mu.Lock()
	if p.closed || p.claimed || !p.rpcPreparing {
		err = cryptov4.ErrTransition
	} else {
		for _, target := range []*resourcev4.Reference{&r.dispatch, &r.notification} {
			*target, err = p.reservation.Borrow()
			if err != nil {
				break
			}
		}
	}
	p.mu.Unlock()
	if err != nil {
		return err
	}
	for i, needed := range r.registryNeeded {
		if needed {
			r.registryBorrows[i], err = c.ExecutionRegistry.Borrow(refs[rpcServicesMetadata])
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func rpcRegistryReferences(c RPCServicesConfig) [3]bool {
	return [3]bool{c.Session.Limits().ApplicationProfile == "execution" && c.ExecutionRegistry != nil, c.ExecutionRegistry != nil, c.notificationConfig().ExecutionSlots != 0}
}

func (r *rpcServicesReferences) aliases() [11]*resourcev4.Reference {
	return [11]*resourcev4.Reference{
		&r.shortExecution, &r.callerResult, &r.callerOwner[0], &r.callerOwner[1], &r.callerOwner[2], &r.callerAuthority,
		&r.dispatch, &r.notification,
		&r.registryBorrows[0], &r.registryBorrows[1], &r.registryBorrows[2],
	}
}

func (r *rpcServicesReferences) check(b *rpcServicesBatch) error {
	if !b.prepared || b.used || r.plan != b.plan || r.registry != b.config.ExecutionRegistry || r.registryNeeded != rpcRegistryReferences(b.config) {
		return resourcev4.ErrOwner
	}
	for i, ref := range r.aliases() {
		if i >= 8 && !r.registryNeeded[i-8] {
			if *ref != (resourcev4.Reference{}) {
				return resourcev4.ErrOwner
			}
			continue
		}
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (r *rpcServicesReferences) move() error {
	for _, ref := range r.aliases() {
		if *ref == (resourcev4.Reference{}) {
			continue
		}
		moved, err := ref.TakeBorrow()
		if err != nil {
			return err
		}
		*ref = moved
	}
	return nil
}

func (r *rpcServicesReferences) close() {
	for _, ref := range r.aliases() {
		ref.Release()
	}
	*r = rpcServicesReferences{}
}
