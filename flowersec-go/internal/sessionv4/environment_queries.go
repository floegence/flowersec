package sessionv4

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ContractQueryRefusal preserves the authenticated fixed SDK refusal code. It
// carries no business execution identity and never grants retry or dispatch.
type ContractQueryRefusal struct{ Code uint64 }

func (ContractQueryRefusal) Error() string { return "sessionv4: fixed contract query refused" }

// ContractQuerySnapshots owns detached validated canonical bytes and metadata,
// not a service binding or current authorization. It does not retain a Session.
type ContractQuerySnapshots struct {
	mu      sync.Mutex
	backing resourcev4.Reference
	items   [8]protocolv4.ContractSnapshotInfo
	bodies  [8][]byte
	count   int
	closed  bool
}

func ContractQuerySnapshotsCharge(count int) (resourcev4.Vector, error) {
	if count < 1 || count > 8 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ContractQuerySnapshots{})) + uint64(count)*(8192+128), resourcev4.Items: 1}, nil
}
func (s *ContractQuerySnapshots) Count() int {
	if s == nil {
		return 0
	}
	return s.count
}
func (s *ContractQuerySnapshots) Item(index int) (protocolv4.ContractSnapshotInfo, error) {
	if s == nil {
		return protocolv4.ContractSnapshotInfo{}, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || index < 0 || index >= s.count {
		return protocolv4.ContractSnapshotInfo{}, cryptov4.ErrClosed
	}
	if err := s.backing.Check(); err != nil {
		return protocolv4.ContractSnapshotInfo{}, err
	}
	return s.items[index], nil
}
func (s *ContractQuerySnapshots) CopyCanonical(index int, dst []byte) (int, error) {
	if s == nil {
		return 0, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || index < 0 || index >= s.count {
		return 0, cryptov4.ErrClosed
	}
	if err := s.backing.Check(); err != nil {
		return 0, err
	}
	n := int(s.items[index].ContractBytes)
	if len(dst) < n {
		return 0, cryptov4.ErrCapacity
	}
	return copy(dst, s.bodies[index][:n]), nil
}
func (s *ContractQuerySnapshots) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for i := range s.bodies {
		clear(s.bodies[i])
		s.bodies[i] = nil
	}
	s.items = [8]protocolv4.ContractSnapshotInfo{}
	s.backing.Release()
	s.backing = resourcev4.Reference{}
}

// ContractQueryAcquisition is one of the Environment's original two or four
// acquisition positions. It remains indexed until its root worker, decoder,
// response and old request provider tail have actually exited.
type ContractQueryAcquisition struct {
	mu                                    sync.Mutex
	environment                           *Environment
	session                               *EnvironmentSession
	plan                                  *SessionPlan
	ctx                                   context.Context
	deadline                              *timev4.Deadline
	publisher                             *rpcv4.Publisher
	initiator                             *rpcv4.ContractQueryInitiator
	registration                          *sdkQueryRegistration
	call                                  rpcv4.ContractQueryCall
	decoder                               *rpcv4.ContractQueryDecode
	snapshots                             *ContractQuerySnapshots
	targets                               [8]protocolv4.ContractQueryTarget
	known                                 [8]*protocolv4.ServiceContract
	windows                               [8]uint64
	count, index, offset                  int
	phase                                 uint8
	ready, done                           chan struct{}
	complete, closed, workerExited, taken bool
	failure                               error
}

// BeginContractQuery admits the complete detached destination and finite
// acquisition before a root worker can publish the original request. It uses
// an existing channel; no acquisition opens a channel, retries or borrows an
// ordinary application/Completion permit.
func (e *Environment) BeginContractQuery(ctx context.Context, s *EnvironmentSession, publisher *rpcv4.Publisher, targets []protocolv4.ContractQueryTarget, known []*protocolv4.ServiceContract, windows []uint64, deadlineMS uint64, destination resourcev4.Reference) (*ContractQueryAcquisition, error) {
	if e == nil || s == nil || ctx == nil || publisher == nil || len(known) != len(targets) || len(windows) != len(targets) {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ContractQuerySnapshotsCharge(len(targets))
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.closed || s.environment != e || s.closed || s.drain != nil || !s.delivered || s.core == nil || s.application == nil {
		return nil, cryptov4.ErrClosed
	}
	slot := -1
	for i, q := range e.queries {
		if q == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		return nil, cryptov4.ErrCapacity
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = e.reservation.Check(); err != nil {
		return nil, err
	}
	if err = e.shared.Check(); err != nil {
		return nil, err
	}
	if err = destination.CheckSameEnvironment(e.reservation); err != nil {
		return nil, err
	}
	plan := s.application
	plan.mu.Lock()
	if plan.closed || !plan.claimed || plan.queries == nil || plan.queries.initiator.Load() == nil {
		plan.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	initiator, group, executor := plan.queries.initiator.Load(), &plan.queries.group, plan.executor
	borrow, err := plan.reservation.Borrow()
	plan.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer borrow.Release()
	if _, a, err := plan.queryAuthorization(); err != nil {
		return nil, err
	} else if err = a.Check(); err != nil {
		return nil, err
	}
	deadline, err := timev4.NewDeadline(e.materialClock, deadlineMS)
	if err != nil {
		return nil, err
	}
	backing, err := destination.Take(charge)
	if err != nil {
		return nil, err
	}
	snapshots := &ContractQuerySnapshots{backing: backing, count: len(targets)}
	q := &ContractQueryAcquisition{environment: e, session: s, plan: plan, ctx: ctx, deadline: deadline, publisher: publisher, initiator: initiator, snapshots: snapshots, count: len(targets), ready: make(chan struct{}), done: make(chan struct{})}
	for i, target := range targets {
		q.targets[i] = target
		q.targets[i].Namespace = strings.Clone(target.Namespace)
		q.known[i] = known[i]
		q.windows[i] = windows[i]
		snapshots.bodies[i] = make([]byte, 8192)
	}
	// Register with the owner gate held: a coalesced root source wake may arrive
	// immediately, before the explicit first Wake below.
	q.mu.Lock()
	q.registration, err = executor.registerSDKQuery(group, 1, q, borrow)
	if err != nil {
		q.mu.Unlock()
		snapshots.Close()
		return nil, err
	}
	e.queries[slot] = q
	e.queryActive++
	q.mu.Unlock()
	q.registration.Wake()
	e.signalMaterials()
	return q, nil
}

func (q *ContractQueryAcquisition) checkLocked() error {
	if q.closed {
		return cryptov4.ErrClosed
	}
	if err := q.ctx.Err(); err != nil {
		return err
	}
	if err := q.deadline.Check(); err != nil {
		return err
	}
	if err := q.snapshots.backing.Check(); err != nil {
		return err
	}
	_, a, err := q.plan.queryAuthorization()
	if err != nil {
		return err
	}
	return a.Check()
}
func (q *ContractQueryAcquisition) finishLocked(err error) {
	if err != nil && q.failure == nil && !q.taken {
		q.failure = err
	}
	if !q.complete {
		q.complete = true
		close(q.ready)
	}
	if err != nil {
		q.closed = true
		q.registration.Close()
	}
}
func (q *ContractQueryAcquisition) queryStep() (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.complete {
		return false, nil
	}
	if err := q.checkLocked(); err != nil {
		q.finishLocked(err)
		return false, nil
	}
	var err error
	switch q.phase {
	case 0:
		q.call, err = q.initiator.Begin(q.publisher, q.targets[:q.count], q.known[:q.count], q.deadline.Cap())
		if err == nil {
			q.phase = 1
		}
	case 1:
		var progress rpcv4.CompletionProgress
		progress, err = q.call.Progress()
		if err == nil && !progress.Complete {
			return false, nil
		}
		if err == nil && (progress.Abandoned || progress.Reason != "") {
			err = rpcv4.ErrClosed
		}
		if err == nil && progress.Header.IsSDKError() {
			err = ContractQueryRefusal{Code: progress.SDKErrorCode}
		}
		if err == nil {
			q.decoder, err = q.call.BeginDecode(q.known[:q.count], q.windows[:q.count], q.snapshots.bodies[:q.count])
			if errors.Is(err, rpcv4.ErrCapacity) {
				return false, nil
			}
			if err == nil {
				q.phase = 2
			}
		}
	case 2:
		var done bool
		done, err = q.decoder.Step()
		if done && err == nil {
			var set protocolv4.ContractSnapshotSet
			set, err = q.decoder.Result()
			if err == nil {
				for i := 0; i < q.count; i++ {
					q.snapshots.items[i], err = set.Item(i)
					if err != nil {
						break
					}
				}
				q.decoder.Close()
				q.decoder = nil
				q.call.Close()
				q.phase = 3
			}
		}
	case 3:
		// An unchanged response still becomes an owned public snapshot. Copy its
		// actual retained known body in the same fixed lane, at most 4 KiB per turn.
		if q.index == q.count {
			q.finishLocked(nil)
			return false, nil
		}
		info := &q.snapshots.items[q.index]
		if info.Status != "available_unchanged" {
			q.index++
			return true, nil
		}
		known := q.known[q.index]
		var size, n int
		size, err = known.CanonicalSize()
		if err == nil {
			n, err = known.CopyCanonicalRange(q.snapshots.bodies[q.index][q.offset:min(q.offset+4096, size)], q.offset)
			q.offset += n
		}
		if err == nil && q.offset == size {
			info.ContractBytes = uint16(size)
			q.index++
			q.offset = 0
		}
	}
	if err != nil {
		q.finishLocked(err)
		return false, nil
	}
	return true, nil
}
func (q *ContractQueryAcquisition) queryClose() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.finishLocked(cryptov4.ErrClosed)
	if q.decoder != nil {
		q.decoder.Close()
		q.decoder = nil
	}
	q.call.Close()
	if q.snapshots != nil {
		q.snapshots.Close()
		q.snapshots = nil
	}
	q.known = [8]*protocolv4.ServiceContract{}
	q.targets = [8]protocolv4.ContractQueryTarget{}
	q.plan, q.publisher, q.initiator = nil, nil, nil
	q.workerExited = true
	if q.environment != nil {
		q.environment.signalMaterials()
	}
}
func (q *ContractQueryAcquisition) Close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	if !q.complete {
		q.finishLocked(cryptov4.ErrClosed)
	}
	q.registration.Close()
}
func (q *ContractQueryAcquisition) Wait(ctx context.Context) error {
	if q == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.ready:
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.failure
}
func (q *ContractQueryAcquisition) WaitCleanup(ctx context.Context) error {
	if q == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.done:
		return nil
	}
}

// Take transfers exactly once under original Environment, Session, lease,
// caller and deadline gates. Cancellation of a short Wait never calls this.
func (q *ContractQueryAcquisition) Take() (*ContractQuerySnapshots, error) {
	if q == nil {
		return nil, cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	if q.taken {
		q.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if q.failure != nil {
		err := q.failure
		q.mu.Unlock()
		return nil, err
	}
	e, s := q.environment, q.session
	q.mu.Unlock()
	if e == nil || s == nil {
		return nil, cryptov4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if e.closed || s.closed || q.closed || q.taken || q.snapshots == nil {
		return nil, cryptov4.ErrClosed
	}
	if q.failure != nil {
		return nil, q.failure
	}
	if !q.complete {
		return nil, cryptov4.ErrCapacity
	}
	if err := q.checkLocked(); err != nil {
		q.finishLocked(err)
		q.closed = true
		q.registration.Close()
		return nil, err
	}
	lease, a, err := q.plan.queryAuthorization()
	if err != nil {
		return nil, err
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.revoked || lease.authorization != a {
		return nil, ErrApplicationAuthorization
	}
	if err := q.ctx.Err(); err != nil {
		return nil, err
	}
	if err := q.deadline.Check(); err != nil {
		q.finishLocked(err)
		return nil, err
	}
	if err := e.reservation.Check(); err != nil {
		q.finishLocked(err)
		return nil, err
	}
	if err := e.shared.Check(); err != nil {
		q.finishLocked(err)
		return nil, err
	}
	result := q.snapshots
	q.snapshots = nil
	q.taken, q.closed = true, true
	q.registration.Close()
	return result, nil
}

// The existing Environment timer supervises these finite original contexts
// and tails even when no query is ready, without a watcher per acquisition.
func (e *Environment) watchContractQueriesLocked() bool {
	active := false
	for i, q := range e.queries {
		if q == nil {
			continue
		}
		active = true
		q.mu.Lock()
		if !q.closed {
			err := q.ctx.Err()
			if err == nil {
				err = q.deadline.Check()
			}
			if err == nil {
				err = e.reservation.Check()
			}
			if err == nil {
				err = e.shared.Check()
			}
			if err != nil {
				q.finishLocked(err)
				q.closed = true
				q.registration.Close()
			}
		}
		if q.workerExited && q.call.CleanupComplete() {
			select {
			case <-q.registration.done:
				q.environment, q.session, q.ctx, q.deadline = nil, nil, nil, nil
				q.call = rpcv4.ContractQueryCall{}
				q.registration = nil
				e.queries[i] = nil
				e.queryActive--
				close(q.done)
			default:
			}
		}
		q.mu.Unlock()
	}
	return active
}
