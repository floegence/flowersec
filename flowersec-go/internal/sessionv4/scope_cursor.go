package sessionv4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ScopeReaderCursor keeps the callback lifetime fence around the original
// cursor. A view owns at most one unsettled cursor, including a dormant or
// detached candidate. Scope exit explicitly closes that original owner.
type ScopeReaderCursor struct {
	view   *ScopeStream
	cursor *ReaderCursor
}

func ScopeReaderCursorCharge(storageBytes uint64) (resourcev4.Vector, error) {
	charge, err := ReaderCursorCharge(storageBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ScopeReaderCursor{})), resourcev4.Items: 1})
}

func (v *ScopeStream) ExactReaderCursor(k, capacity uint64, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ScopeReaderCursor, error) {
	target, err := exactCursorTarget(k, capacity)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	return v.newCursor(target, reservation, authorization)
}

func (v *ScopeStream) UntilReaderCursor(delimiter []byte, maximum, capacity uint64, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ScopeReaderCursor, error) {
	target, err := untilCursorTarget(delimiter, maximum, capacity)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	return v.newCursor(target, reservation, authorization)
}

func (v *ScopeStream) newCursor(target cursorTarget, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ScopeReaderCursor, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed || v.owner == nil {
		return nil, cursorConstructionError(ErrStreamOwned)
	}
	if v.cursor != nil {
		return nil, cursorConstructionError(ErrReadInProgress)
	}
	if authorization == nil {
		return nil, cursorConstructionError(ErrCursorTarget)
	}
	if err := reservation.CheckSameEnvironment(v.owner.reservation); err != nil {
		return nil, cursorConstructionError(err)
	}
	charge, err := ScopeReaderCursorCharge(target.limit)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	// Take the complete facade+cursor backing before the original cursor's
	// handoff. Take preserves the entire charge, not just its minimum.
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	defer owned.Release() // Becomes stale after successful original handoff.
	o := v.owner
	_, _, f, _, err := o.begin()
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	defer o.end()
	cursor, err := admitOwnedReaderCursor(f.receive, target, owned, authorization, o)
	if err != nil {
		return nil, err
	}
	v.cursor = &ScopeReaderCursor{view: v, cursor: cursor}
	return v.cursor, nil
}

func (c *ScopeReaderCursor) read(ctx context.Context, mode uint8) (protocolv4.V4ReadResult, error) {
	if _, err := c.view.begin(); err != nil {
		return protocolv4.V4ReadResult{}, cursorConstructionError(err)
	}
	var result protocolv4.V4ReadResult
	var err error
	switch mode {
	case 0:
		result, err = c.cursor.ReadExactly(ctx)
	case 1:
		result, err = c.cursor.ReadUntil(ctx)
	case 2:
		result, err = c.cursor.ReadLine(ctx)
	default:
		result, err = c.cursor.TakePrefix(ctx)
	}
	snapshot := c.cursor.Progress()
	if snapshot.Delivered || snapshot.Closed {
		c.settled()
	}
	c.view.end(snapshot.Delivered && result.WaitStatus == protocolv4.V4WaitStatusReady && result.StreamStatus == protocolv4.V4StreamStatusEof)
	return result, err
}

func (c *ScopeReaderCursor) ReadExactly(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, 0)
}
func (c *ScopeReaderCursor) ReadUntil(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, 1)
}
func (c *ScopeReaderCursor) ReadLine(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, 2)
}
func (c *ScopeReaderCursor) TakePrefix(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, 3)
}
func (c *ScopeReaderCursor) Progress() protocolv4.V4ReaderCursorSnapshot {
	return c.cursor.Progress()
}
func (c *ScopeReaderCursor) Close() {
	c.cursor.Close()
	c.settled()
}
func (c *ScopeReaderCursor) settled() {
	c.view.mu.Lock()
	if c.view.cursor == c {
		c.view.cursor = nil
	}
	c.view.mu.Unlock()
}
