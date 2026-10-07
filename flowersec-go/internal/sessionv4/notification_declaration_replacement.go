package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func replacementDeclarationCharge(ctx context.Context, declarations []ServiceDependency) (resourcev4.Vector, error) {
	if ctx == nil {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return resourcev4.Vector{}, err
	}
	if application, err := checkApplicationContext(ctx); err != nil {
		return resourcev4.Vector{}, err
	} else if application {
		return resourcev4.Vector{}, ErrApplicationDependency
	}
	return serviceDependenciesCharge(declarations)
}

// ReplaceDependencies changes a local observer declaration through its
// original owner. It neither queries contracts nor prepares network paths.
func (s *NotificationSubscription) ReplaceDependencies(ctx context.Context, declarations []ServiceDependency) error {
	if s == nil {
		return cryptov4.ErrConfiguration
	}
	charge, err := replacementDeclarationCharge(ctx, declarations)
	if err != nil {
		return err
	}
	s.mu.Lock()
	n, token := s.controller, s.token
	var dispatch *NotificationDispatch
	if token != nil {
		dispatch = token.dispatch
	}
	s.mu.Unlock()
	if n != nil {
		return n.replaceDependencies(ctx, declarations, charge)
	}
	if dispatch == nil {
		return rpcv4.ErrClosed
	}
	return dispatch.replaceObserverDependencies(ctx, token, declarations, charge)
}

func (d *NotificationDispatch) replaceObserverDependencies(ctx context.Context, token *notificationToken, declarations []ServiceDependency, charge resourcev4.Vector) error {
	d.mu.Lock()
	if d.closed || token.closed || token.dispatch != d || token.preparing {
		d.mu.Unlock()
		return rpcv4.ErrClosed
	}
	if d.declarationPreparing || token.declarationPreparing || d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return rpcv4.ErrCapacity
	}
	d.declarationPreparing, token.declarationPreparing = true, true
	d.serial++
	serial, owner, root, accounts, count := d.serial, d.owner, d.root, d.accounts, d.accountCount
	method := token.method.method.Method
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.declarationPreparing, token.declarationPreparing = false, false
		if token.closed {
			token.advanceLocked(timev4.Sample{})
		}
		d.cleanupLocked()
		d.mu.Unlock()
	}()
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
	err = d.withAuthority(method, func(notificationMethod) error {
		if token.closed || token.dispatch != d {
			return rpcv4.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		previous, token.services = token.services, next
		// The first declaration has a separate original primary. Transfer
		// that ownership to its real callback/view tail before replacing it.
		if previous != nil && token.dependencies != (resourcev4.Reference{}) {
			previous.mu.Lock()
			previous.ownedPrimary = true
			previous.mu.Unlock()
			token.dependencies = resourcev4.Reference{}
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

func (n *controllerNotificationRoot) replaceDependencies(ctx context.Context, declarations []ServiceDependency, charge resourcev4.Vector) error {
	n.mu.Lock()
	if n.closed || n.preparing || n.cleaned {
		n.mu.Unlock()
		return rpcv4.ErrClosed
	}
	if n.declarationPreparing || n.serial == math.MaxUint64 {
		n.mu.Unlock()
		return rpcv4.ErrCapacity
	}
	n.declarationPreparing = true
	n.serial++
	serial, owner, root, accounts, count := n.serial, n.owner, n.root, n.accounts, n.accountCount
	n.mu.Unlock()
	defer func() { n.mu.Lock(); n.declarationPreparing = false; n.mu.Unlock() }()
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
	n.mu.Lock()
	if n.closed || ctx.Err() != nil {
		n.mu.Unlock()
		return rpcv4.ErrClosed
	}
	previous := n.services
	n.services, installed = next, true
	n.mu.Unlock()
	previous.close()
	return nil
}

// ReplaceDependencies keeps the unique execution handler and exact registered
// notification contract. Observation-only methods have no handler declaration.
func (d *NotificationDispatch) ReplaceDependencies(ctx context.Context, selector UnaryMethodSelector, declarations []ServiceDependency) error {
	if d == nil || selector.Namespace == "" || selector.Type == 0 {
		return cryptov4.ErrConfiguration
	}
	charge, err := replacementDeclarationCharge(ctx, declarations)
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
	index := -1
	for i, method := range d.methods {
		if method.policy.Namespace == selector.Namespace && method.policy.Type == selector.Type && method.method.ExecutionHandler != nil {
			index = i
			break
		}
	}
	if index < 0 {
		d.mu.Unlock()
		return rpcv4.ErrMethod
	}
	d.declarationPreparing = true
	d.serial++
	serial, owner, root, accounts, count := d.serial, d.owner, d.root, d.accounts, d.accountCount
	method := d.methods[index].method.Method
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
	err = d.withAuthority(method, func(notificationMethod) error {
		if d.draining.Load() {
			return rpcv4.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		previous, d.methods[index].method.services = d.methods[index].method.services, next
		installed = true
		return nil
	})
	if err != nil {
		return err
	}
	previous.close()
	return nil
}
