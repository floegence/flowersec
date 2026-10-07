package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Only constructors hold this gate. It orders two original endpoint mutexes;
// neither I/O nor cleanup depends on it or adds a private worker.
var duplexHandoffGate sync.Mutex

// NewOwnedDuplexBridge transfers two unused raw handles from their original
// Sessions in one Environment. All old aliases lose both I/O directions before
// the constructor returns. Admission failure preserves both original owners.
func NewOwnedDuplexBridge(ctx context.Context, a, b *StreamOwnership, options DuplexOptions) (*DuplexBridge, error) {
	if a == nil || b == nil || a == b {
		return nil, cryptov4.ErrConfiguration
	}
	duplexHandoffGate.Lock()
	defer duplexHandoffGate.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.admission == nil || b.admission == nil || a.admission == b.admission && a.handle.scope == b.handle.scope ||
		a.allocationRoot == nil || a.allocationRoot != b.allocationRoot {
		return nil, ErrStreamOwned
	}
	return newOwnedDuplexBridgeLocked(ctx, [2]*StreamOwnership{a, b}, nil, options)
}

// NewOwnedNativeDuplexBridge transfers one original raw Stream and a sealed
// SDK-created native TCP endpoint. It never adopts an arbitrary net.Conn.
func NewOwnedNativeDuplexBridge(ctx context.Context, stream *StreamOwnership, native *NativeTCP, options DuplexOptions) (*DuplexBridge, error) {
	if stream == nil || native == nil || native.nativeTCPCore == nil {
		return nil, cryptov4.ErrConfiguration
	}
	// Freeze the canonical core even if the caller replaces its opaque handle.
	endpoint := *native
	duplexHandoffGate.Lock()
	defer duplexHandoffGate.Unlock()
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return newOwnedDuplexBridgeLocked(ctx, [2]*StreamOwnership{stream, nil}, &endpoint, options)
}

// The caller holds each non-nil original owner mutex. All runtime, result,
// ownership and bounded copy backing is reserved before either owner moves.
func newOwnedDuplexBridgeLocked(ctx context.Context, original [2]*StreamOwnership, native *NativeTCP, options DuplexOptions) (*DuplexBridge, error) {
	if ctx == nil || options.ChunkBytes == 0 || options.ChunkBytes > 1<<20 ||
		options.TimeoutMS == 0 || options.TimeoutMS > 90000 || options.CleanupTimeoutMS == 0 || options.CleanupTimeoutMS > 90000 {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := original[0]
	for _, o := range original {
		if o == nil {
			continue
		}
		if o.admission == nil || o.flow == nil || o.queue == nil || o.allocationRoot == nil ||
			o.allocationRuntimeBytes == 0 || o.cursorSerial == math.MaxUint64 {
			return nil, ErrStreamOwned
		}
		options.RuntimeBytes = max(options.RuntimeBytes, o.allocationRuntimeBytes)
	}
	clock := a.admission.engine.Clock()
	deadline, err := timev4.NewAge(clock, options.TimeoutMS, math.MaxUint64)
	if err != nil {
		return nil, err
	}
	for _, o := range original {
		if o != nil && o.deadline != nil {
			if err = deadline.TightenFrom(o.deadline); err != nil {
				return nil, err
			}
		}
	}
	options.HardDeadline = deadline
	bridgeCharge, err := DuplexBridgeCharge(options)
	if err != nil {
		return nil, err
	}
	copyCharge, err := CopyCharge(options.ChunkBytes)
	if err != nil {
		return nil, err
	}
	copyCharge, err = copyCharge.Add(resourcev4.Vector{resourcev4.SDKBytes: options.RuntimeBytes})
	if err != nil {
		return nil, err
	}
	ownershipCharge := [2]resourcev4.Vector{StreamOwnershipCharge(), StreamOwnershipCharge()}
	if native != nil {
		ownershipCharge[1] = NativeTCPOwnershipCharge()
	}
	// Bridge coordination and each directional copy retain both original
	// account ancestries. Endpoint-owner metadata remains in its own scopes.
	var sharedScopes [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	sharedCount := 0
	for _, o := range original {
		if o == nil {
			continue
		}
		for _, account := range o.allocationScopes[:o.allocationCount] {
			found := false
			for _, existing := range sharedScopes[:sharedCount] {
				if existing == account {
					found = true
					break
				}
			}
			if found {
				continue
			}
			if sharedCount == len(sharedScopes) {
				return nil, resourcev4.ErrCapacity
			}
			sharedScopes[sharedCount] = account
			sharedCount++
		}
	}
	var requests [5]resourcev4.Request
	var references [5]resourcev4.Reference
	for index, charge := range [5]resourcev4.Vector{bridgeCharge, ownershipCharge[0], ownershipCharge[1], copyCharge, copyCharge} {
		o := a
		if original[1] != nil && (index == 2 || index == 4) {
			o = original[1]
		}
		var identity [33]byte
		copy(identity[:8], "duplex4/")
		copy(identity[8:24], o.allocationOwner.Backing[:])
		binary.BigEndian.PutUint64(identity[24:32], o.cursorSerial+1)
		identity[32] = byte(index)
		digest := sha256.Sum256(identity[:])
		owner := o.allocationOwner
		copy(owner.Backing[:], digest[:16])
		accounts := o.allocationScopes[:o.allocationCount]
		if index == 0 || index >= 3 || (native != nil && index == 2) {
			accounts = sharedScopes[:sharedCount]
		}
		requests[index] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: accounts}
	}
	if err = a.allocationRoot.ReserveBatch(requests[:], references[:]); err != nil {
		return nil, err
	}
	defer func() {
		for _, reference := range references {
			reference.Release()
		}
	}()
	var b OpenHandle
	if original[1] != nil {
		b = original[1].handle
	}
	d, tasks, err := prepareDuplexBridgeMode(ctx, a.handle, b, native, options, references[0],
		[2]resourcev4.Reference{references[1], references[2]}, [2]resourcev4.Reference{references[3], references[4]}, original)
	if err != nil {
		return nil, err
	}
	for _, o := range original {
		if o != nil {
			o.cursorSerial++
		}
	}
	for i := range 2 {
		go d.worker(i, tasks.context, tasks.workers[i])
	}
	go d.supervise(ctx, d.clock, d.cleanupMS, tasks.supervisor)
	return d, nil
}

// The caller holds both original endpoint mutexes. Lock the distinct admission,
// send and receive gates before checking either endpoint. No operation can
// enter between validation and the all-or-nothing slot-owner replacement.
func handoffDuplexOwners(original [2]*StreamOwnership, references [2]resourcev4.Reference, deadline *timev4.Deadline, ctx context.Context, abort <-chan struct{}) (_ [2]*StreamOwnership, err error) {
	var next [2]*StreamOwnership
	// Original callback contexts remain supervised by the same bridge workers.
	// Message/connection/recovery compositions cannot surrender their separate
	// owners through this raw facade.
	for _, o := range original {
		if o == nil {
			continue
		}
		if o.admission == nil || o.flow == nil || o.queue == nil || o.users != 0 || o.cleaning || o.rawUsed ||
			o.revoked.Load() || o.sealed.Load() || o.closeRequested.Load() || o.duplexAbort != nil ||
			o.messages != nil || o.typed != nil || o.conn != nil || o.resume != nil || o.recoveryProgress != nil {
			return next, ErrStreamOwned
		}
	}
	if original[1] != nil && (original[0].queue == original[1].queue || original[0].flow.receive == original[1].flow.receive) {
		return next, cryptov4.ErrConfiguration
	}
	for i, o := range original {
		if o == nil {
			continue
		}
		next[i], err = prepareStreamOwnership(references[i])
		if err != nil {
			for _, candidate := range next {
				if candidate != nil {
					candidate.reservation.Release()
				}
			}
			return [2]*StreamOwnership{}, err
		}
	}
	transferred := false
	defer func() {
		if !transferred {
			for _, candidate := range next {
				if candidate != nil {
					candidate.reservation.Release()
				}
			}
		}
	}()
	a := original[0].admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if original[1] != nil && original[1].admission != a {
		original[1].admission.mu.Lock()
		defer original[1].admission.mu.Unlock()
	}
	for _, o := range original {
		if o != nil {
			o.queue.mu.Lock()
			defer o.queue.mu.Unlock()
		}
	}
	pool := original[0].flow.receive.pool
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if original[1] != nil && original[1].flow.receive.pool != pool {
		original[1].flow.receive.pool.mu.Lock()
		defer original[1].flow.receive.pool.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return [2]*StreamOwnership{}, err
	}
	if err := deadline.Check(); err != nil {
		return [2]*StreamOwnership{}, err
	}
	for i, o := range original {
		if o == nil {
			continue
		}
		s, err := o.admission.slot(o.handle)
		if err != nil {
			return [2]*StreamOwnership{}, err
		}
		q, f := o.queue, o.flow.receive
		if o.admission.closed || s.owner != o || s.cancelled || !s.accepted || s.cleanupBusy || s.coreCleaned ||
			q.writeOwner != o || f.readOwner != o || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 ||
			f.readPending || f.readTails != 0 || f.readerCursor != nil || q.rawUsed || f.rawUsed || f.cleaned ||
			q.closed || q.sealed || f.pool.closed {
			return [2]*StreamOwnership{}, ErrStreamOwnershipBusy
		}
		if err := o.checkLifetime(); err != nil {
			return [2]*StreamOwnership{}, err
		}
		if err := o.admission.engine.CheckApplicationAuthorization(); err != nil {
			return [2]*StreamOwnership{}, err
		}
		if err := next[i].reservation.CheckSameEnvironment(o.reservation); err != nil {
			return [2]*StreamOwnership{}, err
		}
	}
	for i, o := range original {
		if o == nil {
			continue
		}
		n := next[i]
		n.admission, n.handle, n.flow, n.queue = o.admission, o.handle, o.flow, o.queue
		n.cap, n.deadline, n.operationContext = o.cap, deadline, ctx
		n.closeAdmission.Store(o.admission)
		n.allocationRoot, n.allocationRuntimeBytes = o.allocationRoot, o.allocationRuntimeBytes
		s, _ := o.admission.slot(o.handle)
		// Exactly one retirement reference remains with the replacement owner.
		s.owner, o.queue.writeOwner, o.flow.receive.readOwner = n, n, n
		// Fence obsolete aliases without stopping the unchanged queue or flow.
		o.duplexAbort = abort
		o.revoked.Store(true)
		o.sealed.Store(true)
		close(o.done)
		close(o.revokeDone)
		o.admission, o.flow, o.queue = nil, nil, nil
		o.closeAdmission.Store(nil)
		o.deadline, o.operationContext = nil, nil
		o.allocationRoot = nil
		o.allocationExecutor, o.allocationGroup = nil, nil
		o.allocationExecutionBacking.Release()
		o.allocationExecutionBacking = resourcev4.Reference{}
		o.allocationOwner = resourcev4.OwnerKey{}
		clear(o.allocationScopes[:])
		o.allocationCount = 0
		o.handle = OpenHandle{}
		o.reservation.Release()
		o.reservation = resourcev4.Reference{}
		o.notify()
	}
	transferred = true
	return next, nil
}
