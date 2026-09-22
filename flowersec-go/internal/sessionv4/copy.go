package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var errCopyTargetClosed = errors.New("sessionv4: copy destination acceptance closed")

// CopyResult owns the last, not-yet-accepted source suffix. No field retains a
// transport or reservation. A successful copy proves source EOF and local
// destination acceptance only; it does not send FIN or prove remote receipt.
type CopyResult struct {
	Progress protocolv4.V4TransferProgress
	// SourceTerminal is the last read observation. A source may subsequently
	// terminate while destination acceptance waits; a lifecycle owner must
	// reconcile that endpoint's state before claiming overall completion.
	SourceTerminal protocolv4.V4ReadTerminal
}

// CopyProgress is a coherent metadata snapshot. It never exposes the chunk
// while a pump can still change it. Complete means the original pump returned,
// independently of endpoint Finish, physical cleanup or result handoff.
type CopyProgress struct {
	SourceReadBytes, DestinationAcceptedBytes, PendingTailBytes uint64
	SourceTerminal                                              protocolv4.V4ReadTerminal
	Complete                                                    bool
}

// copyState has exactly one advancing caller. Source consumption and target
// acceptance update it synchronously inside their respective original gates;
// it is never inferred from Stream-wide counters or delayed continuations.
type copyState struct {
	mu                      sync.Mutex
	storage                 []byte
	filled, accepted        int
	sourceRead, targetTaken uint64
	reservation             resourcev4.Reference
	sourceOwner             *StreamOwnership
	targetOwner             *StreamOwnership
	nativeOwner             *nativeTCPOwnership
	targetDone              <-chan struct{}
	terminal                protocolv4.V4ReadTerminal
	started, complete       bool
	final                   CopyResult
}

// CopyCharge reserves the single chunk, result and synchronous pump metadata.
// The profile also accounts actual host stack and allocator overhead. There is
// no private queue, worker, timer, cursor, or per-chunk operation allocation.
func CopyCharge(chunkBytes uint64) (resourcev4.Vector, error) {
	metadata := uint64(unsafe.Sizeof(copyState{})) + uint64(unsafe.Sizeof(CopyResult{}))
	if chunkBytes == 0 || chunkBytes > uint64(math.MaxInt)-metadata {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: chunkBytes + metadata, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, nil
}

// Copy holds the original source read position until its actual return. It
// processes one chunk's remaining suffix before reading more, using ordinary
// destination FIFO acceptance. Concurrent destination writers keep those same
// FIFO semantics. Neither direction is implicitly finished or reset.
//
// This internal composition requires both endpoints and the chunk reservation
// to belong to the same Environment and budget root. Returned tail backing is
// synchronously handed to the caller; until then its entire allocation remains
// charged even when only a small suffix is still unaccepted.
func Copy(ctx context.Context, dst *SendQueue, src *ReceiveFlow, chunkBytes uint64, reservation resourcev4.Reference) (CopyResult, error) {
	return copyOwned(ctx, dst, src, chunkBytes, reservation, nil, nil)
}

func copyOwned(ctx context.Context, dst *SendQueue, src *ReceiveFlow, chunkBytes uint64, reservation resourcev4.Reference, sourceOwner, targetOwner *StreamOwnership) (CopyResult, error) {
	result := CopyResult{SourceTerminal: protocolv4.V4ReadTerminalUnknown}
	_, err := CopyCharge(chunkBytes)
	if err != nil || ctx == nil || dst == nil || src == nil {
		return result, cryptov4.ErrConfiguration
	}
	if err := claimCopy(dst, src, reservation, sourceOwner, targetOwner); err != nil {
		return result, err
	}
	s, err := prepareCopy(chunkBytes, reservation)
	if err != nil {
		releaseCopyClaim(dst, src, sourceOwner)
		return result, err
	}
	defer func() { releaseCopyClaim(dst, src, sourceOwner); s.release() }()
	s.sourceOwner, s.targetOwner, s.targetDone = sourceOwner, targetOwner, dst.writeDone
	s.started = true
	return s.run(ctx, dst, src)
}

// prepareCopy admits the complete backing before any read. Its charge remains
// with the composition until it explicitly hands off the frozen result; an SDK
// worker returning to another SDK worker is not an application handoff.
func prepareCopy(chunkBytes uint64, reservation resourcev4.Reference) (*copyState, error) {
	charge, err := CopyCharge(chunkBytes)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &copyState{storage: make([]byte, int(chunkBytes)), reservation: owned, terminal: protocolv4.V4ReadTerminalUnknown}, nil
}

func claimCopy(dst *SendQueue, src *ReceiveFlow, reservation resourcev4.Reference, sourceOwner, targetOwner *StreamOwnership) (err error) {
	if err := dst.beginWriteMethod(targetOwner); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			dst.endWriteMethod()
		}
	}()
	// Read the mutable queue reservation under its original cleanup gate.
	dst.mu.Lock()
	err = dst.writeOwnershipLocked(targetOwner)
	if err == nil {
		err = reservation.CheckSameEnvironment(dst.reservation)
	}
	dst.mu.Unlock()
	if err != nil {
		return err
	}
	src.pool.mu.Lock()
	if err = src.readOwnershipLocked(sourceOwner); err != nil {
		src.pool.mu.Unlock()
		return err
	}
	if src.readPending {
		src.pool.mu.Unlock()
		return ErrReadInProgress
	}
	if err = reservation.CheckSameEnvironment(src.reservation); err != nil {
		src.pool.mu.Unlock()
		return err
	}
	src.readPending = true
	src.pool.mu.Unlock()
	return nil
}

func releaseCopyClaim(dst *SendQueue, src *ReceiveFlow, sourceOwner *StreamOwnership) {
	src.pool.mu.Lock()
	src.readPending = false
	sourceOwner.notify()
	src.pool.mu.Unlock()
	dst.endWriteMethod()
}

// runOwned keeps canonical endpoint aliases through every actual method tail.
// It runs synchronously on an already admitted composition worker.
func (s *copyState) runOwned(ctx context.Context, source, target *StreamOwnership) (CopyResult, error) {
	s.mu.Lock()
	if s.started || s.complete {
		s.mu.Unlock()
		return CopyResult{}, ErrStreamOwned
	}
	s.started = true
	s.mu.Unlock()
	defer func() {
		// Admission can fail before run reaches the first read. Freeze that
		// valid empty result too, and detach its unused chunk allocation.
		if s.final.SourceTerminal == "" {
			s.result(protocolv4.V4ReadTerminalUnknown)
		}
		s.mu.Lock()
		s.sourceOwner, s.targetOwner, s.targetDone = nil, nil, nil
		s.complete = true
		s.mu.Unlock()
	}()
	result := CopyResult{SourceTerminal: protocolv4.V4ReadTerminalUnknown}
	if ctx == nil || source == nil || target == nil || source == target {
		return result, cryptov4.ErrConfiguration
	}
	_, _, src, _, err := source.begin()
	if err != nil {
		return result, err
	}
	defer source.end()
	_, _, dst, queue, err := target.begin()
	if err != nil {
		return result, err
	}
	defer target.end()
	if src.receive.engine == dst.receive.engine && src.receive.scope == dst.receive.scope {
		return result, cryptov4.ErrConfiguration
	}
	if err := claimCopy(queue, src.receive, s.reservation, source, target); err != nil {
		return result, err
	}
	defer releaseCopyClaim(queue, src.receive, source)
	s.sourceOwner, s.targetOwner, s.targetDone = source, target, queue.writeDone
	return s.run(ctx, queue, src.receive)
}

func (s *copyState) run(ctx context.Context, dst *SendQueue, src *ReceiveFlow) (CopyResult, error) {
	for {
		terminal, readErr := src.copyRead(ctx, s)
		if readErr != nil {
			if readErr == errCopyTargetClosed {
				// Resolve the original destination cause after leaving the source
				// gate; two streams may share a receive pool with queue->pool locks.
				dst.mu.Lock()
				readErr = dst.requestErrorLocked(s.targetOwner)
				dst.mu.Unlock()
				if readErr == nil {
					readErr = ErrFlowClosed
				}
			}
			return s.result(terminal), boundedReadCause(readErr)
		}
		for s.accepted < s.filled {
			_, err := dst.writeMethodOwned(ctx, s.storage[s.accepted:s.filled], s, s.targetOwner, true)
			if err != nil {
				return s.result(terminal), boundedReadCause(err)
			}
		}
		if terminal == protocolv4.V4ReadTerminalEof {
			return s.result(terminal), nil
		}
	}
}

// copyRead reuses the original read gates while keeping the direction claim
// across destination waits. Thus neither another reader nor Cleanup can take
// over between chunks, including when an EOF chunk is waiting for acceptance.
func (f *ReceiveFlow) copyRead(ctx context.Context, s *copyState) (observed protocolv4.V4ReadTerminal, readErr error) {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	defer func() { s.mu.Lock(); s.terminal = observed; s.mu.Unlock() }()
	for {
		select {
		case <-s.targetDone:
			return protocolv4.V4ReadTerminalUnknown, errCopyTargetClosed
		default:
		}
		if err := s.checkOwners(); err != nil {
			return protocolv4.V4ReadTerminalUnknown, err
		}
		if err := f.readOwnershipLocked(s.sourceOwner); err != nil {
			return protocolv4.V4ReadTerminalUnknown, err
		}
		terminal, err := f.readStatusLocked()
		if terminal != protocolv4.V4ReadTerminalOpen || err != nil {
			return terminal, err
		}
		if err := ctx.Err(); err != nil {
			return terminal, err
		}
		if err := s.reservation.Check(); err != nil {
			return terminal, err
		}
		if f.size != 0 {
			n := min(f.size, len(s.storage))
			if s.accepted != s.filled || uint64(n) > math.MaxUint64-s.sourceRead {
				return terminal, ErrStreamData
			}
			s.mu.Lock()
			n, terminal, err = f.readCopyLocked(s.storage)
			s.filled, s.accepted = n, 0
			s.sourceRead += uint64(n)
			s.terminal = terminal
			s.mu.Unlock()
			return terminal, err
		}
		p.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-ownershipWake(s.sourceOwner):
		case <-ownershipWake(s.targetOwner):
		case <-s.targetDone:
		case <-p.done:
		case <-f.readWake:
		}
		p.mu.Lock()
	}
}

func (s *copyState) checkAcceptance(n int) error {
	if err := s.checkOwners(); err != nil {
		return err
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if n < 0 || n > s.filled-s.accepted || uint64(n) > math.MaxUint64-s.targetTaken {
		return ErrStreamData
	}
	return nil
}

func (s *copyState) sourceWake() <-chan struct{} {
	if s == nil {
		return nil
	}
	return ownershipWake(s.sourceOwner)
}

// Both endpoint capabilities govern a Copy for its entire lifetime, including
// the phase that is currently waiting on the opposite endpoint's data/credit.
func (s *copyState) checkOwners() error {
	if s == nil {
		return nil
	}
	if s.nativeOwner != nil {
		if err := s.nativeOwner.checkLifetime(); err != nil {
			return err
		}
	}
	for _, owner := range [2]*StreamOwnership{s.sourceOwner, s.targetOwner} {
		if owner != nil {
			if owner.revoked.Load() || owner.sealed.Load() {
				return ErrStreamOwned
			}
			if err := owner.checkLifetime(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *copyState) accept(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.storage[s.accepted : s.accepted+n])
	s.accepted += n
	s.targetTaken += uint64(n)
}

func (s *copyState) result(terminal protocolv4.V4ReadTerminal) CopyResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	var tail []byte
	if s.accepted < s.filled {
		tail = s.storage[s.accepted:s.filled:s.filled]
	}
	s.storage = nil
	s.terminal = terminal
	s.final = CopyResult{Progress: protocolv4.V4TransferProgress{SourceReadBytes: s.sourceRead, DestinationAcceptedBytes: s.targetTaken, UnacceptedTail: tail}, SourceTerminal: terminal}
	return s.final
}

func (s *copyState) progress() CopyProgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return CopyProgress{SourceReadBytes: s.sourceRead, DestinationAcceptedBytes: s.targetTaken, PendingTailBytes: uint64(s.filled - s.accepted), SourceTerminal: s.terminal, Complete: s.complete}
}

// release is called after the advancing worker exited and its final payload
// was handed to the application, or before any worker on failed construction.
func (s *copyState) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storage = nil
	s.sourceOwner, s.targetOwner, s.targetDone = nil, nil, nil
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
}
