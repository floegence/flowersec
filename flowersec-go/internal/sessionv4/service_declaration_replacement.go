package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ReplaceServiceDependencies replaces only the trusted dependency declaration
// of an existing unary, streaming or notification execution registration. The immutable method shape,
// handler and contract remain owned by the original Session dispatcher.
func (s *EnvironmentSession) ReplaceServiceDependencies(ctx context.Context, method UnaryMethodSelector, declarations []ServiceDependency) error {
	if s == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	core, err := s.Core()
	if err != nil {
		return err
	}
	core.plan.mu.Lock()
	r := core.plan.rpc
	core.plan.mu.Unlock()
	if r == nil {
		return cryptov4.ErrNotReady
	}
	r.mu.Lock()
	d, notifications := r.dispatch, r.notifications
	r.mu.Unlock()
	if d != nil {
		err = d.ReplaceDependencies(ctx, method, declarations)
		if !errors.Is(err, rpcv4.ErrMethod) {
			return err
		}
	}
	if notifications != nil {
		return notifications.ReplaceDependencies(ctx, method, declarations)
	}
	return rpcv4.ErrMethod
}

// Construction owns one finite registration turn. New required declarations
// qualify before publication; closing the previous declaration only revokes
// future uses, and its original invocation/selected-view visits retain backing.
func (d *ServiceDispatch) ReplaceDependencies(ctx context.Context, selector UnaryMethodSelector, declarations []ServiceDependency) (err error) {
	if d == nil || ctx == nil || selector.Namespace == "" || selector.Type == 0 {
		return cryptov4.ErrConfiguration
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if application, e := checkApplicationContext(ctx); e != nil {
		return e
	} else if application {
		return ErrApplicationDependency
	}
	charge, err := serviceDependenciesCharge(declarations)
	if err != nil {
		return err
	}
	d.mu.Lock()
	if d.closed || d.draining.Load() {
		d.mu.Unlock()
		return rpcv4.ErrClosed
	}
	if d.declarationPreparing || d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return rpcv4.ErrCapacity
	}
	kind, index := uint8(0), -1
	for i, m := range d.methods {
		if m.registration.Namespace == selector.Namespace && m.registration.Type == selector.Type {
			kind, index = 1, i
			break
		}
	}
	if index < 0 {
		for i, m := range d.streamMethods {
			if m.registration.Namespace == selector.Namespace && m.registration.Type == selector.Type {
				kind, index = 2, i
				break
			}
		}
	}
	if index < 0 {
		d.mu.Unlock()
		return rpcv4.ErrMethod
	}
	d.declarationPreparing = true
	d.serial++
	serial, owner, root := d.serial, d.owner, d.root
	accounts, count := d.accounts, d.accountCount
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.declarationPreparing = false; d.cleanupLocked(); d.mu.Unlock() }()
	next, err := allocateReplacementDependencies(declarations, charge, root, owner, serial, accounts[:count])
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			next.close()
		}
	}()
	var previous *invocationServices
	err = d.withDeclarationAuthority(ctx, func() error {
		if kind == 1 {
			previous, d.methods[index].registration.services = d.methods[index].registration.services, next
		} else {
			previous, d.streamMethods[index].registration.services = d.streamMethods[index].registration.services, next
		}
		installed = true
		return nil
	})
	if err != nil {
		return err
	}
	previous.close()
	return nil
}

func allocateReplacementDependencies(declarations []ServiceDependency, charge resourcev4.Vector, root *resourcev4.Root, owner resourcev4.OwnerKey, serial uint64, accounts []resourcev4.Account) (*invocationServices, error) {
	if len(declarations) == 0 {
		return nil, nil
	}
	var seed [48]byte
	copy(seed[:16], "declarations/v4")
	copy(seed[16:32], owner.Backing[:])
	binary.BigEndian.PutUint64(seed[32:40], serial)
	digest := sha256.Sum256(seed[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	backing, err := root.Reserve(owner, charge, accounts...)
	if err != nil {
		return nil, err
	}
	next, err := newInvocationServices(declarations, backing)
	if err != nil {
		backing.Release()
		return nil, err
	}
	next.ownedPrimary = true
	return next, nil
}

// The replacement turn pins this original dispatcher while the established
// endpoint and application lease recheck the local publication decision.
func (d *ServiceDispatch) withDeclarationAuthority(ctx context.Context, action func() error) error {
	d.mu.Lock()
	p := d.plan
	d.mu.Unlock()
	if p == nil {
		return rpcv4.ErrClosed
	}
	lease, authority, err := p.queryAuthorization()
	if err != nil {
		return err
	}
	return authority.WithCurrentAuthorizationSample(func(timev4.Sample) error {
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if lease.revoked || !lease.authorized || lease.authorization != authority {
			return ErrApplicationAuthorization
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed || d.draining.Load() {
			return rpcv4.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return action()
	})
}
