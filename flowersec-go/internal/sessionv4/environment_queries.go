package sessionv4

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ContractQueryRefusal preserves the authenticated fixed SDK refusal code. It
// carries no business execution identity and never grants retry or dispatch.
type ContractQueryRefusal struct{ Code uint64 }

func (ContractQueryRefusal) Error() string { return "sessionv4: fixed contract query refused" }

// ContractQuerySnapshots owns detached validated canonical bytes and metadata,
// not a service binding or current authorization. It does not retain a Session.
type ContractQuerySnapshots struct {
	mu        sync.Mutex
	backing   resourcev4.Reference
	items     [8]protocolv4.ContractSnapshotInfo
	validated protocolv4.ContractSnapshotSet
	bodies    [8][]byte
	count     int
	closed    bool
	borrows   uint8
}

func ContractQuerySnapshotsCharge(count int) (resourcev4.Vector, error) {
	if count < 1 || count > 8 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ContractQuerySnapshots{})) + uint64(count)*(8192+256), resourcev4.Items: 1}, nil
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
	s.releaseLocked()
}

func (s *ContractQuerySnapshots) releaseLocked() {
	if !s.closed || s.borrows != 0 {
		return
	}
	for i := range s.bodies {
		clear(s.bodies[i])
		s.bodies[i] = nil
	}
	s.items = [8]protocolv4.ContractSnapshotInfo{}
	s.validated = protocolv4.ContractSnapshotSet{}
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
	known                                 [8]protocolv4.ContractQueryKnown
	windows                               [8]uint64
	count, index, offset                  int
	phase                                 uint8
	ready, done                           chan struct{}
	complete, closed, workerExited, taken bool
	consumerHeld                          bool
	protection                            *contractQueryProtection
	failure                               error
	dependencies                          applicationDependencies
	knownOwners                           [8]*ContractQuerySnapshots
	diagnosticOperation                   *DiagnosticOperation
}

// BeginContractQuery admits the complete detached destination and finite
// acquisition before a root worker can publish the original request. It uses
// an existing channel; no acquisition opens a channel, retries or borrows an
// ordinary application/Completion permit.
func (e *Environment) BeginContractQuery(ctx context.Context, s *EnvironmentSession, publisher *rpcv4.Publisher, targets []protocolv4.ContractQueryTarget, known []protocolv4.ContractQueryKnown, windows []uint64, deadlineMS uint64, destination resourcev4.Reference) (*ContractQueryAcquisition, error) {
	return e.beginContractQuery(ctx, s, publisher, targets, known, windows, deadlineMS, nil, nil, destination)
}

func (e *Environment) beginContractQuery(ctx context.Context, s *EnvironmentSession, publisher *rpcv4.Publisher, targets []protocolv4.ContractQueryTarget, known []protocolv4.ContractQueryKnown, windows []uint64, deadlineMS uint64, original *timev4.Deadline, claim *contractQueryClaim, destination resourcev4.Reference) (*ContractQueryAcquisition, error) {
	if e == nil || s == nil || ctx == nil || publisher == nil || len(known) != len(targets) || len(windows) != len(targets) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := validateContractQueryTargets(targets, known); err != nil {
		return nil, err
	}
	var dependencyFloor *resourcev4.BorrowPool
	s.mu.Lock()
	application := s.application
	s.mu.Unlock()
	if application != nil {
		application.mu.Lock()
		dependencyFloor = application.dependencyFloor
		application.mu.Unlock()
	}
	dependencies, err := captureApplicationDependenciesWithFloor(ctx, dependencyFloor)
	if err != nil {
		return nil, err
	}
	defer dependencies.release()
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
	if claim == nil && e.queryActive+uint32(e.staticContractWork) >= e.ordinaryContractWorkLimitLocked() {
		return nil, cryptov4.ErrCapacity
	}
	slot := -1
	if claim != nil {
		if claim.environment != e || claim.index < 0 || claim.index >= len(e.queries) || e.queryClaims[claim.index] != claim || e.queries[claim.index] != nil {
			return nil, cryptov4.ErrConfiguration
		}
		slot = claim.index
	} else {
		for i := range e.queries {
			if e.ordinaryContractQuerySlotLocked(i) {
				slot = i
				break
			}
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
	var protection *contractQueryProtection
	if claim != nil {
		protection = claim.protection
	}
	var borrow resourcev4.Reference
	if protection == nil {
		borrow, err = plan.reservation.Borrow()
	} else if protection.closed || e.queryProtection != protection || protection.session != s || protection.plan != plan {
		err = cryptov4.ErrClosed
	} else {
		err = protection.lane.CheckInitiator(initiator)
	}
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
	deadline := original
	if deadline == nil {
		deadline, err = timev4.NewDeadline(e.materialClock, deadlineMS)
	} else if !deadline.BelongsTo(e.materialClock) || deadline.Cap() != deadlineMS {
		err = timev4.ErrOwner
	} else {
		err = deadline.Check()
	}
	if err != nil {
		return nil, err
	}
	backing, err := destination.Take(charge)
	if err != nil {
		return nil, err
	}
	snapshots := &ContractQuerySnapshots{backing: backing, count: len(targets)}
	diagnosticOperation := diagnosticOperationFromContext(ctx)
	if claim != nil && claim.diagnosticOperation != nil {
		diagnosticOperation = claim.diagnosticOperation
	} else if !diagnosticOperationOwnedFromContext(ctx) {
		diagnosticOperation = nil
	}
	if diagnosticOperation == nil {
		diagnosticOperation = plan.beginApplicationDiagnostic()
		if claim != nil {
			claim.diagnosticOperation = diagnosticOperation
		}
	}
	ctx = withDiagnosticOperation(ctx, diagnosticOperation)
	q := &ContractQueryAcquisition{environment: e, session: s, plan: plan, ctx: ctx, deadline: deadline, publisher: publisher, initiator: initiator, snapshots: snapshots, count: len(targets), ready: make(chan struct{}), done: make(chan struct{}), protection: protection, diagnosticOperation: diagnosticOperation}
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
	if protection == nil {
		q.registration, err = executor.registerSDKQuery(group, 1, q, borrow)
	} else {
		q.registration, err = protection.worker.activate(q)
	}
	if err != nil {
		q.mu.Unlock()
		snapshots.Close()
		finishApplicationDiagnosticError(diagnosticOperation, err)
		if claim != nil && claim.diagnosticOperation == diagnosticOperation {
			claim.diagnosticOperation = nil
		}
		return nil, err
	}
	e.queries[slot] = q
	if claim == nil {
		e.queryActive++
	} else {
		e.queryClaims[slot] = nil
		claim.acquisition = q
		q.consumerHeld = true
	}
	q.dependencies = dependencies
	dependencies = applicationDependencies{}
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
	if err := q.dependencies.checkOrigin(); err != nil {
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
		if q.protection == nil {
			q.call, err = q.initiator.BeginGuarded(q.publisher, q.targets[:q.count], q.known[:q.count], q.deadline.Cap(), q)
		} else {
			q.call, err = q.protection.lane.Begin(q.publisher, q.targets[:q.count], q.known[:q.count], q.deadline.Cap(), q)
		}
		if err == nil {
			err = q.call.RetainConsumer()
		}
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
				q.snapshots.validated = set
				for i := 0; i < q.count; i++ {
					q.snapshots.items[i], err = set.Item(i)
					if err != nil {
						break
					}
					if q.snapshots.items[i].Status == "available_unchanged" {
						var body protocolv4.ContractQueryKnown
						body, err = q.snapshots.validated.Known(i)
						if err != nil {
							break
						}
						var n int
						n, err = body.CanonicalSize()
						if err != nil {
							break
						}
						q.snapshots.items[i].ContractBytes = uint16(n)
					}
				}
				q.decoder.Close()
				q.decoder = nil
				q.call.Close()
				q.phase = 3
			}
		}
	case 3:
		q.finishLocked(nil)
		return false, nil
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
	q.known = [8]protocolv4.ContractQueryKnown{}
	q.targets = [8]protocolv4.ContractQueryTarget{}
	q.plan, q.publisher, q.initiator = nil, nil, nil
	if !q.consumerHeld {
		q.call.ReleaseConsumer()
	}
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
	if _, err := checkApplicationContext(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.ready:
	}
	if err := ctx.Err(); err != nil {
		return err
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
	var result *ContractQuerySnapshots
	err = withApplicationHandoff(q.ctx, func() error {
		if q.protection == nil {
			if err := q.snapshots.backing.DetachSessionScope(); err != nil {
				q.finishLocked(err)
				return err
			}
		}
		result = q.snapshots
		q.snapshots = nil
		// The decoder has exited before complete becomes observable. No
		// later step reads the baseline; actual borrows remain until exit.
		q.known = [8]protocolv4.ContractQueryKnown{}
		q.taken, q.closed = true, true
		q.registration.Close()
		return nil
	})
	return result, err
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
				err = q.dependencies.checkOrigin()
			}
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
		if q.workerExited && !q.consumerHeld && q.call.CleanupComplete() {
			select {
			case <-q.registration.done:
				q.dependencies.release()
				for i, owner := range q.knownOwners {
					if owner != nil {
						owner.releaseQueryBorrow()
						q.knownOwners[i] = nil
					}
				}
				finishApplicationDiagnosticError(q.diagnosticOperation, q.failure)
				q.diagnosticOperation = nil
				q.environment, q.session, q.ctx, q.deadline = nil, nil, nil, nil
				q.call = rpcv4.ContractQueryCall{}
				q.registration = nil
				q.protection = nil
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

// Publication checks the original acquisition immediately before every new
// request fragment. Cancel/expiry cannot race a queued query into a fresh
// BEGIN, and cleanup fragments keep the publisher's separate tail rights.
func (q *ContractQueryAcquisition) WithRequestPublication(h protocolv4.ApplicationHeader, action func() error) error {
	if q == nil || action == nil || h.Kind() != "query_contracts_request" {
		return cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.complete || q.plan == nil {
		return cryptov4.ErrClosed
	}
	if err := q.checkLocked(); err != nil {
		q.finishLocked(err)
		return err
	}
	if h.Fields().DeadlineAtMS != q.deadline.Cap() {
		return rpcv4.ErrAssociation
	}
	lease, authority, err := q.plan.queryAuthorization()
	if err != nil {
		return err
	}
	return authority.WithCurrentAuthorization(func() error {
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if lease.revoked || !lease.authorized || lease.authorization != authority {
			return ErrApplicationAuthorization
		}
		if err := q.ctx.Err(); err != nil {
			return err
		}
		return withApplicationHandoff(q.ctx, action)
	})
}

func (*ContractQuerySnapshots) String() string               { return "Flowersec.ContractQuerySnapshots" }
func (*ContractQuerySnapshots) GoString() string             { return "Flowersec.ContractQuerySnapshots" }
func (*ContractQuerySnapshots) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
