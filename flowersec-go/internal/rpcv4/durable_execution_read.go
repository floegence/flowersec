package rpcv4

import (
	"context"
	"math"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func DurableExecutionResultReadCharge(limit uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if limit > 1048576 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	charge, err := ExecutionResultReadCharge(runtimeBytes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(limit) + uint64(unsafe.Sizeof(executionResult{})), resourcev4.Items: 1})
}

// CaptureResult runs on the original admitted provider task. It copies the
// complete bounded result before any publication, checks its digest in the
// store, and lends only finite in-memory chunks to the existing publisher.
func (s *DurableExecutions) CaptureResult(ctx context.Context, target ExecutionTarget, access ExecutionAccess, metadata resourcev4.Reference, limit uint32, runtimeBytes uint64) (read *ExecutionResultRead, err error) {
	if s == nil || s.durableExecutions == nil || ctx == nil || access == nil {
		return nil, ErrConfiguration
	}
	q, err := s.targetRequest(target)
	if err != nil {
		return nil, err
	}
	charge, err := DurableExecutionResultReadCharge(limit, runtimeBytes)
	if err != nil {
		return nil, err
	}
	if err = s.beginCall(false); err != nil {
		return nil, err
	}
	defer s.endCall()
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		if s.joins == math.MaxUint32 {
			return ErrCapacity
		}
		if err := metadata.CheckSameEnvironment(s.reservation); err != nil {
			return err
		}
		if err := metadata.CheckSameEnvironment(authority); err != nil {
			return err
		}
		owned, err := metadata.Take(charge)
		if err != nil {
			return err
		}
		pin, err := authority.Borrow()
		if err != nil {
			owned.Release()
			return err
		}
		target.Service = s.config.Service
		target.Caller.Subject = strings.Clone(target.Caller.Subject)
		read = &ExecutionResultRead{durable: s, clock: s.config.Clock, target: target, access: access, reservation: owned, authority: pin, result: &executionResult{payload: make([]byte, limit)}}
		s.joins++
		return nil
	})
	if err != nil {
		return nil, err
	}
	originalRead := read
	defer func() {
		if err != nil {
			originalRead.Close()
			read = nil
		}
	}()
	o, n, err := s.config.Store.ReadResult(ctx, q, read.result.payload, func() error { return s.checkAccess(target, access) })
	if err != nil {
		return read, durableExecutionError(err)
	}
	// Zero retention grants only original pre-exit response joins, never a new
	// read_result request even while the task is still leaving its callback.
	if o.ResultNotAfterMS == 0 {
		return read, ErrResultExpired
	}
	read.result.length, read.result.written, read.result.code = uint32(n), uint32(n), o.ApplicationErrorCode
	read.result.digest, read.result.expires, read.result.formed = o.ResultDigest, o.ResultNotAfterMS, true
	return read, nil
}
