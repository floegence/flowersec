package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
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
	b, err := a.PrepareBootstrap(BootstrapReservation{StreamReservation: allocation.stream.reservation,
		Receiver: n.readers[0].receiver, reusableReceiver: true})
	if err != nil {
		allocation.release()
		return nil, err
	}
	r.firstAllocation, r.bootstrap, r.native = allocation, b, n
	return b, nil
}

// openInternal uses the original native association for every RPC, notify and
// management generation. The fixed future already owns its receive workspace;
// native creation cannot turn pressure into a second channel allocation.
func (r *RPCServices) openInternal(ctx context.Context, class StreamClass, kind string, allocation *internalChannelAllocation, deadline *timev4.Deadline) (OpenHandle, RecordWriteResult, error) {
	a := r.bootstrap.admission
	association := &CarrierAssociation{shared: a.sharedIngress}
	if r.native != nil {
		s, err := r.native.open(ctx)
		if err != nil {
			return OpenHandle{}, RecordWriteResult{}, err
		}
		defer r.native.finishOpen(s)
		association = &s.association
		allocation.stream.reservation.Writer = s.stream
	}
	return a.OpenLocal(ctx, class, kind, nil, association, allocation.stream.reservation, deadline)
}
