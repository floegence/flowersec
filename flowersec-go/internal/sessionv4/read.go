package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

var (
	ErrReadInput      = errors.New("sessionv4: read destination must be nonempty")
	ErrReadInProgress = errors.New("sessionv4: read in progress")
)

// ReadTransfer is the internal borrowed-destination projection. ReadInto never
// retains dst beyond the call and does not claim ownership of its memory. The
// public owned Read/ReadChunk facade uses its own pre-admitted result storage.
// Internal errors still require the public bounded typed-error projection.
type ReadTransfer struct {
	Progress     protocolv4.V4ReadProgress
	WaitStatus   protocolv4.V4WaitStatus
	ReadTerminal protocolv4.V4ReadTerminal
}

func (f *ReceiveFlow) signalReadLocked() {
	select {
	case f.readWake <- struct{}{}:
	default:
	}
}

// ReadInto holds the sole original read position through waiting and the
// synchronous copy. Cancellation before that copy leaves the queue untouched;
// cancellation after its claim cannot erase transferred bytes. It never starts
// a goroutine, installs a per-call notification, or waits while holding a gate.
// A committed EOF/abort/failure wins over cancellation of this wait.
func (f *ReceiveFlow) ReadInto(ctx context.Context, dst []byte) (ReadTransfer, error) {
	return f.readIntoOwned(ctx, dst, nil)
}

func (f *ReceiveFlow) readIntoOwned(ctx context.Context, dst []byte, owner *StreamOwnership) (ReadTransfer, error) {
	if ctx == nil || len(dst) == 0 {
		return ReadTransfer{}, ErrReadInput
	}
	p := f.pool
	p.mu.Lock()
	if err := f.readOwnershipLocked(owner); err != nil {
		p.mu.Unlock()
		return ReadTransfer{}, err
	}
	if f.readPending {
		p.mu.Unlock()
		return ReadTransfer{}, ErrReadInProgress
	}
	f.readPending = true
	for {
		if err := f.readOwnershipLocked(owner); err != nil {
			f.readPending = false
			f.notifyCleanupLocked()
			p.mu.Unlock()
			return ReadTransfer{}, err
		}
		terminal, err := f.readStatusLocked()
		result := ReadTransfer{Progress: protocolv4.V4ReadProgress{Offset: f.delivered}, WaitStatus: protocolv4.V4WaitStatusReady, ReadTerminal: terminal}
		if terminal != protocolv4.V4ReadTerminalOpen || err != nil {
			f.readPending = false
			f.notifyCleanupLocked()
			p.mu.Unlock()
			return result, err
		}
		if err := ctx.Err(); err != nil {
			result.WaitStatus = protocolv4.V4WaitStatusWaitCanceled
			f.readPending = false
			f.notifyCleanupLocked()
			p.mu.Unlock()
			return result, err
		}
		if f.size != 0 {
			// The cancellation check and fixed byte range above are the local
			// irrevocable claim. The actual copy completes in this same gate;
			// Reset and cleanup cannot erase it or return the credit twice.
			n, terminal, err := f.readCopyLocked(dst)
			result.Progress.Offset, result.Progress.Filled = f.delivered, uint64(n)
			result.ReadTerminal = terminal
			f.readPending = false
			f.notifyCleanupLocked()
			p.mu.Unlock()
			return result, err
		}
		p.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-ownershipWake(owner):
		case <-p.done:
		case <-f.readWake:
		}
		p.mu.Lock()
	}
}
