package rpcv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type ContentObservation = ledgerv4.SQLiteContentObservation

// ContentMethod is trusted local application composition. The exact definition
// includes the position/selection codecs and existing unary ReadType semantics.
type ContentMethod struct {
	Type, ReadType uint32
	Definition     [32]byte
}

type executionContentItem struct {
	position      [256]byte
	positionBytes uint16
	offset        uint32
	observation   ContentObservation
}
type executionContent struct {
	reservation            resourcev4.Reference
	policy                 protocolv4.StreamContentPolicy
	readType               uint32
	admitted, latestExpiry uint64
	items                  []executionContentItem
	payload                []byte
	count, used            uint32
}

func validateContentMethods(methods []ContentMethod) error {
	if len(methods) > 128 {
		return ErrConfiguration
	}
	for i, m := range methods {
		if m.Type == 0 || m.ReadType == 0 || m.ReadType == m.Type || m.Definition == ([32]byte{}) {
			return ErrConfiguration
		}
		for _, previous := range methods[:i] {
			if previous.Type == m.Type {
				return ErrConfiguration
			}
		}
	}
	return nil
}

func (s *VolatileExecutions) supportsContent(p protocolv4.ServiceContractPolicy) bool {
	if s == nil || !p.RetainedContent || p.Shape != 1 || p.Semantics != 1 || p.ExecutionMode != 0 || p.Content.RetentionOrigin > 1 || p.Content.RetentionMS == 0 || p.Content.MaxItems == 0 || p.Content.MaxItems > 1024 || p.Content.MaxBytes == 0 || p.Content.MaxBytes > 1048576 {
		return false
	}
	for _, m := range s.contentMethods {
		if m.Type == p.Type && m.Definition == p.Content.Definition {
			return true
		}
	}
	return false
}
func (s *VolatileExecutions) ContentReadType(typeID uint32) uint32 {
	if s == nil {
		return 0
	}
	for _, m := range s.contentMethods {
		if m.Type == typeID {
			return m.ReadType
		}
	}
	return 0
}
func executionContentCharge(p protocolv4.StreamContentPolicy) (resourcev4.Vector, error) {
	if p.MaxItems == 0 || p.MaxItems > 1024 || p.MaxBytes == 0 || p.MaxBytes > 1048576 {
		return resourcev4.Vector{}, ErrExecutionUnsupported
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(executionContent{})) + p.MaxItems*uint64(unsafe.Sizeof(executionContentItem{})) + p.MaxBytes, resourcev4.Items: 1 + p.MaxItems}, nil
}
func (c *executionContent) close() {
	if c == nil {
		return
	}
	clear(c.payload)
	clear(c.items)
	c.payload = nil
	c.items = nil
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
}
func (c *executionContent) find(position []byte) *executionContentItem {
	for i := uint32(0); i < c.count; i++ {
		item := &c.items[i]
		if bytes.Equal(item.position[:item.positionBytes], position) {
			return item
		}
	}
	return nil
}

// SaveContent has the same explicit position and fixed-origin semantics as
// durable storage, confined to this actual volatile owner's lifetime. The
// complete archive was admitted together with this original execution.
func (w *ExecutionWork) SaveContent(ctx context.Context, position, payload []byte) (out ContentObservation, err error) {
	if w == nil || ctx == nil || len(position) == 0 || len(position) > 256 {
		return out, ErrConfiguration
	}
	w.mu.Lock()
	if w.exited || w.history == nil {
		w.mu.Unlock()
		return out, ErrClosed
	}
	s := w.history
	hold, err := w.reservation.Borrow()
	w.mu.Unlock()
	if err != nil {
		return out, err
	}
	defer hold.Release()
	now, err := s.clock.Sample()
	if err != nil {
		return out, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || !w.entered || w.reported {
		return out, ErrClosed
	}
	err = w.access.WithExecutionAccess(w.target, func(resourcev4.Reference) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		r, err := w.recordLocked()
		if err != nil {
			return err
		}
		if s.closed || r.cancelRequested || r.state != ExecutionExecuting {
			return ErrClosed
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = w.deadline.CheckAt(now); err != nil {
			return err
		}
		if err = w.run.CheckAt(now); err != nil {
			return err
		}
		c := r.content
		if c == nil {
			return ErrExecutionUnsupported
		}
		if err = c.reservation.Check(); err != nil {
			return err
		}
		if len(payload) > len(c.payload) {
			return ErrCapacity
		}
		digest := sha256.Sum256(payload)
		if item := c.find(position); item != nil {
			o := item.observation
			if o.Bytes != uint32(len(payload)) || o.Digest != digest {
				return ErrExecutionConflict
			}
			o.Expired = now.RetainedThrough(o.ExpiresAtMS)
			o.Available = now.ValidBefore(o.ExpiresAtMS)
			out = o
			return nil
		}
		if c.count >= uint32(len(c.items)) || uint64(len(payload)) > uint64(len(c.payload))-uint64(c.used) {
			return ErrCapacity
		}
		origin := c.admitted
		if c.policy.RetentionOrigin == 1 {
			origin = now.UpperMS
		}
		if c.policy.RetentionMS > math.MaxUint64-origin {
			return ErrConfiguration
		}
		expires := origin + c.policy.RetentionMS
		if !now.ValidBefore(expires) {
			return ErrResultExpired
		}
		o := ContentObservation{Found: true, Available: true, CommittedAtMS: now.UpperMS, ExpiresAtMS: expires, Bytes: uint32(len(payload)), Digest: digest}
		item := &c.items[c.count]
		item.positionBytes = uint16(copy(item.position[:], position))
		item.offset = c.used
		copy(c.payload[c.used:], payload)
		item.observation = o
		c.count++
		c.used += uint32(len(payload))
		c.latestExpiry = max(c.latestExpiry, expires)
		out = o
		return nil
	})
	return out, err
}

func (s *VolatileExecutions) ReadContent(ctx context.Context, target ExecutionTarget, position, dst []byte, readerType uint32, access ExecutionAccess) (out ContentObservation, n int, err error) {
	if s == nil || ctx == nil || access == nil || len(position) == 0 || len(position) > 256 || readerType == 0 {
		return out, 0, ErrConfiguration
	}
	s.mu.Lock()
	hold, err := s.reservation.Borrow()
	s.mu.Unlock()
	if err != nil {
		return out, 0, err
	}
	defer hold.Release()
	now, err := s.clock.Sample()
	if err != nil {
		return out, 0, err
	}
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		if err := s.reservation.CheckSameEnvironment(authority); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := s.keyLocked(target)
		if err != nil {
			return err
		}
		index, _ := s.findLocked(key)
		if index < 0 {
			return ErrHistoryUnknown
		}
		r := &s.records[index]
		if r.request != target.RequestDigest || r.contract != target.ContractDigest {
			return ErrExecutionConflict
		}
		c := r.content
		if c == nil || c.readType != readerType {
			return ErrExecutionUnsupported
		}
		item := c.find(position)
		if item == nil {
			return nil
		}
		out = item.observation
		out.Expired = now.RetainedThrough(out.ExpiresAtMS)
		out.Available = now.ValidBefore(out.ExpiresAtMS)
		if out.Available {
			if uint64(len(dst)) < uint64(out.Bytes) {
				return ErrCapacity
			}
			n = copy(dst, c.payload[item.offset:item.offset+out.Bytes])
		}
		return nil
	})
	if err != nil {
		clear(dst[:n])
		return ContentObservation{}, 0, err
	}
	return out, n, nil
}
