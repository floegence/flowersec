package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Close seals the raw capability and requests the original Stream's abort.
// Actual method tails retain the owner until the existing termination or
// Session cleanup coordinator can relinquish it. No close worker is allocated.
func (o *StreamOwnership) Close() error {
	if o == nil {
		return ErrStreamOwned
	}
	o.mu.Lock()
	if o.admission == nil || o.closeRequested.Load() {
		o.mu.Unlock()
		return nil
	}
	if o.messages != nil || o.typed != nil || o.conn != nil || o.resume != nil {
		o.mu.Unlock()
		return ErrStreamOwned
	}
	a := o.admission
	if err := a.cancelOwned(o.handle, o); err != nil {
		o.mu.Unlock()
		return err
	}
	a.mu.Lock()
	o.queue.mu.Lock()
	o.flow.receive.pool.mu.Lock()
	o.closeRequested.Store(true)
	o.revokeLocked()
	o.flow.receive.pool.mu.Unlock()
	o.queue.mu.Unlock()
	a.mu.Unlock()
	o.mu.Unlock()
	o.releaseClosed()
	return nil
}

func (o *StreamOwnership) releaseClosed() {
	if o == nil || !o.closeRequested.Load() {
		return
	}
	o.mu.Lock()
	var cursor *ReaderCursor
	if o.admission != nil {
		f := o.flow.receive
		f.pool.mu.Lock()
		cursor = f.readerCursor
		f.pool.mu.Unlock()
	}
	o.mu.Unlock()
	if cursor != nil {
		cursor.mu.Lock()
		// Completed private results have detached and retain their independent
		// delivery authority. Only this Stream's incomplete input is abandoned.
		if cursor.flow != nil && cursor.owner == o {
			cursor.closeLocked(ErrStreamOwned)
		}
		cursor.mu.Unlock()
	}
	_ = o.Release() // A busy original tail wakes the original coordinator.
}

// The existing bounded coordinator revisits explicit raw closes without
// waiting for any owner. It takes no owner lock while holding admission.
func (a *OpenAdmission) releaseClosedStreams() {
	a.mu.Lock()
	for i := range a.slots {
		owner := a.slots[i].owner
		if owner == nil || !owner.closeRequested.Load() {
			continue
		}
		// Only an explicit close needs an owner gate. Scan untouched slots
		// under one admission gate, then release it before physical cleanup.
		a.mu.Unlock()
		owner.releaseClosed()
		a.mu.Lock()
	}
	a.mu.Unlock()
}

// reserveCopy uses this Stream's original budget root and account scopes.
// The caller pins ownership throughout allocation and every physical read.
func (o *StreamOwnership) reserveCopy(chunkBytes uint64) (resourcev4.Reference, error) {
	charge, err := CopyCharge(chunkBytes)
	if err != nil || chunkBytes > 1<<20 {
		return resourcev4.Reference{}, cryptov4.ErrConfiguration
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.allocationRoot == nil || o.allocationRuntimeBytes == 0 || o.cursorSerial == math.MaxUint64 {
		return resourcev4.Reference{}, cryptov4.ErrConfiguration
	}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: o.allocationRuntimeBytes})
	if err != nil {
		return resourcev4.Reference{}, err
	}
	o.cursorSerial++
	var identity [32]byte
	copy(identity[:8], "copy4/")
	copy(identity[8:24], o.allocationOwner.Backing[:])
	binary.BigEndian.PutUint64(identity[24:], o.cursorSerial)
	digest := sha256.Sum256(identity[:])
	owner := o.allocationOwner
	copy(owner.Backing[:], digest[:16])
	return o.allocationRoot.Reserve(owner, charge, o.allocationScopes[:o.allocationCount]...)
}

func (o *StreamOwnership) CopyFromStream(ctx context.Context, source *StreamOwnership, chunkBytes uint64) (CopyResult, error) {
	if ctx == nil || source == nil || source == o {
		return CopyResult{}, cryptov4.ErrConfiguration
	}
	if _, _, _, _, err := o.begin(); err != nil {
		return CopyResult{}, err
	}
	defer o.end()
	reservation, err := o.reserveCopy(chunkBytes)
	if err != nil {
		return CopyResult{}, err
	}
	defer reservation.Release()
	return source.CopyTo(ctx, o, chunkBytes, reservation)
}

// CopyFromReader borrows the caller's synchronous Reader. Cancellation cannot
// interrupt arbitrary Reader code; its original buffer and Stream method pin
// remain charged until Read actually returns. Flowersec sources use the
// separate CopyFromStream path, which owns the whole source read position.
func (o *StreamOwnership) CopyFromReader(ctx context.Context, source io.Reader, chunkBytes uint64) (CopyResult, error) {
	if ctx == nil || source == nil {
		return CopyResult{}, cryptov4.ErrConfiguration
	}
	_, _, _, queue, err := o.begin()
	if err != nil {
		return CopyResult{}, err
	}
	defer o.end()
	reservation, err := o.reserveCopy(chunkBytes)
	if err != nil {
		return CopyResult{}, err
	}
	defer reservation.Release()
	s, err := prepareCopy(chunkBytes, reservation)
	if err != nil {
		return CopyResult{}, err
	}
	defer s.release()
	if err := queue.beginWriteMethod(o); err != nil {
		return CopyResult{}, err
	}
	defer queue.endWriteMethod()
	s.targetOwner, s.targetDone, s.started = o, queue.writeDone, true
	for {
		if err := ctx.Err(); err != nil {
			return s.result(protocolv4.V4ReadTerminalUnknown), err
		}
		if err := s.checkOwners(); err != nil {
			return s.result(protocolv4.V4ReadTerminalUnknown), err
		}
		queue.mu.Lock()
		err := queue.requestErrorLocked(o)
		queue.mu.Unlock()
		if err != nil {
			return s.result(protocolv4.V4ReadTerminalUnknown), err
		}
		if err := o.admission.engine.CheckApplicationAuthorization(); err != nil {
			return s.result(protocolv4.V4ReadTerminalUnknown), err
		}
		size := min(uint64(len(s.storage)), math.MaxUint64-s.sourceRead)
		if size == 0 {
			return s.result(protocolv4.V4ReadTerminalUnknown), ErrStreamData
		}
		n, readErr := source.Read(s.storage[:int(size)])
		if n < 0 || uint64(n) > size {
			return s.result(protocolv4.V4ReadTerminalUnknown), ErrReadInput
		}
		s.filled, s.accepted = n, 0
		s.sourceRead += uint64(n)
		terminal := protocolv4.V4ReadTerminalOpen
		if readErr == io.EOF {
			terminal = protocolv4.V4ReadTerminalEof
		}
		for s.accepted < s.filled {
			if _, err := queue.writeMethodOwned(ctx, s.storage[s.accepted:s.filled], s, o, true); err != nil {
				return s.result(terminal), err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				readErr = nil
			}
			return s.result(terminal), readErr
		}
		if n == 0 {
			return s.result(terminal), io.ErrNoProgress
		}
	}
}
