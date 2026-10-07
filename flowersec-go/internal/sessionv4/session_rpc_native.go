package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// prepareNativeBootstrap reserves the same fixed scope before READY. The
// transport's unbound receivers authenticate its actual incoming prefix; they
// remain reusable transport owners and are never closed by scope retirement.
func (r *RPCServices) prepareNativeBootstrap(n *nativeStreamTransport, pool *ReceivePool) (*Bootstrap, error) {
	if r == nil || n == nil || pool == nil || len(n.readers) == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired || r.bootstrap != nil || !r.nativeConfigured {
		return nil, cryptov4.ErrTransition
	}
	a := n.admission
	_, profile := a.engine.SessionBinding()
	if a.engine.SessionParameters().Contract != r.session || a.engine.Clock() != r.clock || profile != r.cryptoProfile {
		return nil, cryptov4.ErrConfiguration
	}
	if err := pool.reservation.CheckAllocationScope(r.root, r.owner, r.accounts[:r.accountCount]); err != nil {
		return nil, err
	}
	if err := n.reservation.CheckAllocationScope(r.root, r.owner, r.accounts[:r.accountCount]); err != nil {
		return nil, err
	}
	if err := r.prepareReceiveLocked(pool); err != nil {
		return nil, err
	}
	allocation, err := r.checkoutChannelAllocationLocked(&r.firstFuture, 0)
	if err != nil {
		return nil, err
	}
	var management [1]*nativeStreamProtection
	if r.session.Limits().ApplicationProfile == "execution" && a.direction == protocolv4.ClientToServer {
		// This same provider and association position survives every M
		// generation. Ordinary native creation cannot consume its promise.
		if err = n.protectLocal(management[:]); err != nil {
			allocation.release()
			return nil, err
		}
		// The bootstrap still needs its original local creation position.
		// Reject insufficient admission before READY instead of stalling it.
		n.mu.Lock()
		bootstrapAvailable := n.openingAvailableLocked(nil)
		n.mu.Unlock()
		if !bootstrapAvailable {
			management[0].close()
			allocation.release()
			return nil, cryptov4.ErrCapacity
		}
	}
	b, err := a.PrepareBootstrap(BootstrapReservation{StreamReservation: allocation.stream.reservation,
		Receiver: n.readers[0].receiver, reusableReceiver: true})
	if err != nil {
		if management[0] != nil {
			management[0].close()
		}
		allocation.release()
		return nil, err
	}
	r.firstAllocation, r.bootstrap, r.native = allocation, b, n
	r.managementNative = management[0]
	return b, nil
}

// openInternal uses the original native association for every RPC, notify and
// management generation. The fixed future already owns its receive workspace;
// native creation cannot turn pressure into a second channel allocation.
func (r *RPCServices) openInternal(ctx context.Context, class StreamClass, kind string, allocation *internalChannelAllocation, deadline *timev4.Deadline) (OpenHandle, RecordWriteResult, error) {
	return r.openInternalObserved(ctx, class, kind, allocation, deadline, nil)
}

func (r *RPCServices) openInternalObserved(ctx context.Context, class StreamClass, kind string, allocation *internalChannelAllocation, deadline *timev4.Deadline, observe func(*nativeStreamSlot, uint64)) (OpenHandle, RecordWriteResult, error) {
	a := r.bootstrap.admission
	association := &CarrierAssociation{shared: a.sharedIngress}
	if r.native != nil {
		var protection *nativeStreamProtection
		if class == ManagementStream {
			protection = r.managementNative
			if protection == nil {
				return OpenHandle{}, RecordWriteResult{}, cryptov4.ErrConfiguration
			}
		}
		s, err := r.native.openProtectedObserved(ctx, protection, observe)
		if err != nil {
			return OpenHandle{}, RecordWriteResult{}, err
		}
		defer r.native.finishOpen(s)
		association = &s.association
		allocation.stream.reservation.Writer = s.stream
	}
	return a.OpenLocal(ctx, class, kind, nil, association, allocation.stream.reservation, deadline)
}
