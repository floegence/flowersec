package rpcv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ManagementRequest is the fixed, narrow control operation carried by the
// execution management stream. Serial is a channel-local correlation value;
// it never replaces the operation identity in Target.
type ManagementRequest struct {
	Serial         uint64
	Target         ExecutionTarget
	History        *VolatileExecutions
	DurableHistory *DurableExecutions
	Continuity     ExecutionContinuity
	Access         ExecutionAccess
	Cancel         bool
}

type ManagementResponse struct {
	Serial      uint64
	Status      string
	Observation ExecutionObservation
	Cancel      ExecutionCancelResult
	IsCancel    bool
}

type managementPending struct {
	serial uint64
	active bool
}

// ExecutionManagement implements the bounded client-side half of the fixed M
// channel. It admits at most limit requests, requires contiguous request
// serials, and never starts application work or a per-request goroutine.
type ExecutionManagement struct {
	mu          sync.Mutex
	reservation resourcev4.Reference
	pending     []managementPending
	next        uint64
	closed      bool
	cleaned     bool
}

func ExecutionManagementCharge(limit uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if limit == 0 || limit > 2 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ExecutionManagement{})) + uint64(limit)*uint64(unsafe.Sizeof(managementPending{})), resourcev4.Items: uint64(limit) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func NewExecutionManagement(limit uint32, runtimeBytes uint64, reservation resourcev4.Reference) (*ExecutionManagement, error) {
	charge, err := ExecutionManagementCharge(limit, runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &ExecutionManagement{reservation: owned, pending: make([]managementPending, limit), next: 1}, nil
}

// Submit performs one complete control request. Admission and execution are
// serialized under the channel gate, while authorization/history implementations
// run only in their own finite SDK callback. A response serial is always the
// original request serial, and serial gaps/future values are rejected.
func (m *ExecutionManagement) Submit(ctx context.Context, req ManagementRequest) (ManagementResponse, error) {
	if m == nil || ctx == nil || req.Access == nil {
		return ManagementResponse{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return ManagementResponse{}, err
	}
	m.mu.Lock()
	if m.closed || m.cleaned {
		m.mu.Unlock()
		return ManagementResponse{}, ErrClosed
	}
	if req.Serial != m.next || req.Serial == 0 || req.Serial == math.MaxUint64 {
		m.mu.Unlock()
		return ManagementResponse{}, ErrAssociation
	}
	index := -1
	for i := range m.pending {
		if !m.pending[i].active {
			index = i
			break
		}
	}
	if index < 0 {
		m.mu.Unlock()
		return ManagementResponse{}, ErrCapacity
	}
	m.pending[index] = managementPending{serial: req.Serial, active: true}
	m.next++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.pending[index] = managementPending{}
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return ManagementResponse{}, err
	}
	return executeManagement(ctx, req)
}

func executeManagement(ctx context.Context, req ManagementRequest) (ManagementResponse, error) {
	if req.Access == nil {
		return ManagementResponse{}, ErrOwner
	}
	if (req.History == nil) == (req.DurableHistory == nil) {
		return ManagementResponse{}, ErrOwner
	}
	var v ExecutionObservation
	var err error
	if req.DurableHistory != nil {
		if req.Cancel {
			v, err = req.DurableHistory.RequestCancel(ctx, req.Target, req.Access)
		} else {
			v, err = req.DurableHistory.Query(ctx, req.Target, req.Access)
		}
		if errors.Is(err, ledgerv4.ErrExecutionHistoryUnknown) {
			v, err = ExecutionObservation{Reason: "history_unknown"}, nil
		} else if err == nil && !v.Found {
			v.Reason = "not_registered"
		}
		if req.Cancel {
			kind := "terminal"
			if !v.Found {
				kind = v.Reason
			} else if v.CancelRequested && v.WorkActive && (v.State == ExecutionAccepted || v.State == ExecutionExecuting || v.State == ExecutionUnknown) {
				kind = "requested"
			}
			return ManagementResponse{Serial: req.Serial, Cancel: ExecutionCancelResult{Kind: kind, Observation: v}, Observation: v, IsCancel: true}, durableExecutionError(err)
		}
	} else if req.Cancel {
		cancel, err := req.History.RequestCancel(req.Target, req.Continuity, req.Access)
		return ManagementResponse{Serial: req.Serial, Cancel: cancel, Observation: cancel.Observation, IsCancel: true}, err
	} else {
		v, err = req.History.Query(req.Target, req.Continuity, req.Access)
	}
	status := "ok"
	if !v.Found {
		status = "history_unknown"
		if v.Reason == "not_registered" {
			status = "not_found"
		}
	} else if v.ResultDeleted {
		status = "result_expired"
	}
	return ManagementResponse{Serial: req.Serial, Status: status, Observation: v}, durableExecutionError(err)
}

func (m *ExecutionManagement) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.cleanupLocked()
}
func (m *ExecutionManagement) cleanupLocked() {
	if !m.closed || m.cleaned {
		return
	}
	for _, p := range m.pending {
		if p.active {
			return
		}
	}
	m.cleaned = true
	clear(m.pending)
	m.reservation.Release()
	m.reservation = resourcev4.Reference{}
}
func (m *ExecutionManagement) CleanupComplete() bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleaned
}
