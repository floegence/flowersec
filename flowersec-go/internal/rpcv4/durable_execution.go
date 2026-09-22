package rpcv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// DurableExecutionConfig admits the finite live adapter, not another business
// history. SQLiteExecutions remains the sole authority for persisted facts.
type DurableExecutionConfig struct {
	Root                           *resourcev4.Root
	Owner                          resourcev4.OwnerKey
	Accounts                       []resourcev4.Account
	Clock                          *timev4.Clock
	Service                        ExecutionService
	Store                          *ledgerv4.SQLiteExecutions
	Active                         uint32
	TaskCharge                     resourcev4.Vector
	RuntimeBytes, WorkRuntimeBytes uint64
}

type DurableExecutions struct{ *durableExecutions }
type durableExecutions struct {
	mu                    sync.Mutex
	config                DurableExecutionConfig
	reservation, storePin resourcev4.Reference
	works                 []*DurableExecutionWork
	floors                []*DurableExecutionAdmission
	reserved, floorCount  uint32
	floorCursor           int
	active                uint32
	calls                 uint32
	joins                 uint32
	serial                uint64
	cursor                int
	closed, cleaned       bool
}

func DurableExecutionsCharge(c DurableExecutionConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.Store == nil || c.Active == 0 || c.Active > 65536 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.RuntimeBytes == 0 || c.WorkRuntimeBytes == 0 || c.TaskCharge[resourcev4.Tasks] == 0 || c.TaskCharge[resourcev4.WorkSlots] == 0 || !executionIdentifier(c.Service.Tenant) || !executionIdentifier(c.Service.Audience) || !executionIdentifier(c.Service.Namespace) {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(DurableExecutions{})) + uint64(unsafe.Sizeof(durableExecutions{})) + uint64(c.Active)*(uint64(unsafe.Sizeof((*DurableExecutionWork)(nil)))+uint64(unsafe.Sizeof((*DurableExecutionAdmission)(nil)))) + uint64(len(c.Accounts))*uint64(unsafe.Sizeof(resourcev4.Account{})) + uint64(len(c.Service.Tenant)+len(c.Service.Audience)+len(c.Service.Namespace))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewDurableExecutions(c DurableExecutionConfig, metadata resourcev4.Reference) (*DurableExecutions, error) {
	charge, err := DurableExecutionsCharge(c)
	if err != nil {
		return nil, err
	}
	if err = metadata.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	pin, err := c.Store.Bind(ledgerv4.SQLiteExecutionService{Tenant: c.Service.Tenant, Audience: c.Service.Audience, Namespace: c.Service.Namespace}, c.Clock, metadata)
	if err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		pin.Release()
		return nil, err
	}
	c.Service = ExecutionService{strings.Clone(c.Service.Tenant), strings.Clone(c.Service.Audience), strings.Clone(c.Service.Namespace)}
	c.Accounts = append([]resourcev4.Account(nil), c.Accounts...)
	return &DurableExecutions{&durableExecutions{config: c, reservation: owned, storePin: pin, works: make([]*DurableExecutionWork, c.Active), floors: make([]*DurableExecutionAdmission, c.Active)}}, nil
}

func (s *DurableExecutions) targetRequest(target ExecutionTarget) (ledgerv4.SQLiteExecutionRequest, error) {
	if s == nil || s.durableExecutions == nil || target.Service != s.config.Service || !executionIdentifier(target.Caller.Subject) {
		return ledgerv4.SQLiteExecutionRequest{}, ErrAssociation
	}
	return ledgerv4.SQLiteExecutionRequest{Key: ledgerv4.SQLiteExecutionKey{CallerAuthority: target.Caller.Authority, CallerSubject: target.Caller.Subject, OperationID: target.Operation}, RequestDigest: target.RequestDigest, ContractDigest: target.ContractDigest}, nil
}

func durableObservation(v ledgerv4.SQLiteExecutionObservation) ExecutionObservation {
	reason := ""
	switch v.Reason {
	case ledgerv4.SQLiteExecutionReasonCancelled:
		reason = "cancel_requested"
	case ledgerv4.SQLiteExecutionReasonDeadline:
		reason = "deadline_exceeded"
	case ledgerv4.SQLiteExecutionReasonOutcomeUnknown:
		reason = "work_outcome_unknown"
	case ledgerv4.SQLiteExecutionReasonNotDispatched:
		reason = "dispatch_unavailable"
	}
	return ExecutionObservation{StreamMetadataOnly: v.StreamMetadataOnly, Found: v.Found, State: ExecutionState(v.State), CancelRequested: v.CancelRequested, Dispatched: v.Dispatched, WorkActive: v.WorkActive, HistoryNotBeforeGCMS: v.HistoryNotBeforeGCMS, ResultNotAfterMS: v.ResultNotAfterMS, ResultAvailable: v.ResultAvailable, ResultDeleted: v.ResultDeleted, ResultBytes: v.ResultBytes, ApplicationErrorCode: v.ApplicationErrorCode, ResultDigest: v.ResultDigest, Reason: reason}
}

func (s *DurableExecutions) checkAccess(target ExecutionTarget, access ExecutionAccess) error {
	if access == nil {
		return ErrConfiguration
	}
	return access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		return s.reservation.CheckSameEnvironment(authority)
	})
}

func (s *DurableExecutions) Query(ctx context.Context, target ExecutionTarget, access ExecutionAccess) (ExecutionObservation, error) {
	q, err := s.targetRequest(target)
	if err != nil {
		return ExecutionObservation{}, err
	}
	err = s.beginCall(false)
	if err != nil {
		return ExecutionObservation{}, err
	}
	defer s.endCall()
	o, err := s.config.Store.Query(ctx, q, func() error { return s.checkAccess(target, access) })
	return durableObservation(o), err
}

func (s *DurableExecutions) ReadResult(ctx context.Context, target ExecutionTarget, access ExecutionAccess, dst []byte) (ExecutionObservation, int, error) {
	q, err := s.targetRequest(target)
	if err != nil {
		return ExecutionObservation{}, 0, err
	}
	err = s.beginCall(false)
	if err != nil {
		return ExecutionObservation{}, 0, err
	}
	defer s.endCall()
	o, n, err := s.config.Store.ReadResult(ctx, q, dst, func() error { return s.checkAccess(target, access) })
	return durableObservation(o), n, err
}

// Admit fixes actual input, route, authority, output and executor responsibility
// before the durable registration. reserve is finite SDK executor admission,
// never application work. Its caller closes an unused acquired permit on every
// duplicate or error; no provider call runs under the finite admission gates.
// A returned work alongside an error owns cleanup only and must be retained.
func (s *DurableExecutions) Admit(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *DurableExecutionWork, error) {
	return s.admit(ctx, routes, input, caller, access, reserve, nil)
}

func (s *DurableExecutions) admit(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, reserve func(resourcev4.Reference, resourcev4.Reference) error, admission *DurableExecutionAdmission) (observation ExecutionObservation, work *DurableExecutionWork, err error) {
	if s == nil || s.durableExecutions == nil || ctx == nil || routes == nil || input == nil || access == nil || reserve == nil {
		return observation, nil, ErrConfiguration
	}
	err = s.beginCall(false)
	if err != nil {
		return observation, nil, err
	}
	defer s.endCall()
	input.mu.Lock()
	h, policy := input.header, input.policy
	input.mu.Unlock()
	target := ExecutionTarget{Service: s.config.Service, Caller: caller, Operation: h.Fields().OperationID, RequestDigest: h.Fields().RequestDigest, ContractDigest: h.Fields().ServiceContractDigest}
	q, err := s.targetRequest(target)
	if err != nil {
		return observation, nil, err
	}
	guard := func() error { return s.checkVerified(target, access, routes, input, h, policy, nil) }
	existing, err := s.config.Store.Query(ctx, q, guard)
	if err != nil {
		return observation, nil, err
	}
	if existing.Found {
		return durableObservation(existing), nil, nil
	}
	revision, err := s.config.Store.RegistrationRevision(ctx, q.ContractDigest, guard)
	if err != nil {
		return observation, nil, err
	}
	q.RegistrationRevision, q.DeadlineAtMS, q.ResponseLimitBytes = revision, h.Fields().DeadlineAtMS, h.Fields().ResponseLimitBytes
	outputCapacity := q.ResponseLimitBytes
	if policy.Shape == 1 {
		outputCapacity = 0
	}
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		input.mu.Lock()
		defer input.mu.Unlock()
		if err := s.checkInputLocked(input, h, policy, nil); err != nil {
			return err
		}
		routes.mu.Lock()
		defer routes.mu.Unlock()
		entry := s.entryLocked(routes, input, policy)
		if entry == nil || !entry.registered {
			return ErrMethod
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		s.refreshAdmissionFloorsLocked()
		if (admission == nil && s.active+s.reserved >= uint32(len(s.works))) || s.active == uint32(len(s.works)) || s.serial == math.MaxUint64 || routes.captures == math.MaxUint32 || input.generation == math.MaxUint64 {
			return ErrCapacity
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.reservation.CheckSameEnvironment(authority); err != nil {
			return err
		}
		if err := s.reservation.CheckSameEnvironment(input.reservation); err != nil {
			return err
		}
		var refs [3]resourcev4.Reference
		var err error
		if admission == nil {
			refs, err = s.reserveWorkLocked(outputCapacity)
		} else {
			refs, err = admission.takeWork(s, outputCapacity, authority)
		}
		if err != nil {
			return err
		}
		var authorityPin resourcev4.Reference
		if admission == nil {
			authorityPin, err = authority.Borrow()
		} else {
			authorityPin = admission.workAuthority
			err = authorityPin.Check()
		}
		if err != nil {
			for _, r := range refs {
				r.Release()
			}
			return err
		}
		fixed, err := input.deadline.Fork(q.DeadlineAtMS)
		if err != nil {
			if admission == nil {
				authorityPin.Release()
			}
			for _, r := range refs {
				r.Release()
			}
			return err
		}
		if err = reserve(refs[1], refs[0]); err != nil {
			if admission == nil {
				authorityPin.Release()
			}
			for _, r := range refs {
				r.Release()
			}
			return err
		}
		index := 0
		for s.works[index] != nil {
			index++
		}
		input.generation++
		input.borrowed = true
		routes.captures++
		target.Caller.Subject = strings.Clone(target.Caller.Subject)
		work = &DurableExecutionWork{&durableExecutionWork{history: s, admission: admission, index: index, routes: routes, entry: entry, input: InputBorrow{input, input.generation}, header: h, policy: policy, target: target, access: access, reservation: refs[0], task: refs[1], storeReservation: refs[2], authority: authorityPin, deadline: fixed, output: make([]byte, outputCapacity), io: true}}
		if admission != nil {
			admission.consumeLocked(s)
			admission.tails.Add(1)
		}
		s.works[index] = work
		s.active++
		return nil
	})
	if err != nil {
		return observation, nil, err
	}
	// The original caller owns work exclusively until this return. Every
	// repeated guard locks only finite SDK state, then returns before SQLite.
	var stored ledgerv4.SQLiteExecutionObservation
	var dbWork *ledgerv4.SQLiteExecutionWork
	if admission == nil {
		stored, dbWork, err = s.config.Store.Register(ctx, q, work.storeReservation, func() error { return s.checkVerified(target, access, routes, input, h, policy, work) })
	} else {
		stored, dbWork, err = s.config.Store.RegisterReserved(ctx, q, work.storeReservation, func() error { return s.checkVerified(target, access, routes, input, h, policy, work) }, admission.capacity)
	}
	work.database = dbWork
	work.storeReservation.Release()
	work.storeReservation = resourcev4.Reference{}
	if dbWork == nil {
		work.releaseLocal()
		work.endIO()
		work = nil
		return durableObservation(stored), nil, err
	}
	work.mu.Lock()
	work.admitted = err == nil
	work.final = durableObservation(stored)
	work.io = false
	work.mu.Unlock()
	return durableObservation(stored), work, err
}

func (s *DurableExecutions) beginCall(retained bool) error {
	if s == nil || s.durableExecutions == nil {
		return ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || s.closed && !retained {
		return ErrClosed
	}
	if s.calls == math.MaxUint32 {
		return ErrCapacity
	}
	var err error
	if retained {
		err = s.reservation.CheckRetained()
	} else {
		err = s.reservation.Check()
	}
	if err != nil {
		return err
	}
	s.calls++
	return nil
}

func (s *DurableExecutions) endCall() { s.mu.Lock(); s.calls--; s.cleanupLocked(); s.mu.Unlock() }

func (s *DurableExecutions) RequestCancel(ctx context.Context, target ExecutionTarget, access ExecutionAccess) (ExecutionObservation, error) {
	q, err := s.targetRequest(target)
	if err != nil {
		return ExecutionObservation{}, err
	}
	err = s.beginCall(false)
	if err != nil {
		return ExecutionObservation{}, err
	}
	defer s.endCall()
	o, err := s.config.Store.RequestCancel(ctx, q, func() error { return s.checkAccess(target, access) })
	if err == nil && o.CancelRequested {
		for i := uint32(0); i < s.config.Active; i++ {
			s.mu.Lock()
			var w *DurableExecutionWork
			if int(i) < len(s.works) {
				w = s.works[i]
			}
			s.mu.Unlock()
			if w != nil {
				w.cancelTarget(target)
			}
		}
	}
	return durableObservation(o), err
}

func (s *DurableExecutions) checkInputLocked(input *VerifiedInput, h protocolv4.ApplicationHeader, p protocolv4.ServiceContractPolicy, w *DurableExecutionWork) error {
	if input.header != h || input.policy != p {
		return ErrAssociation
	}
	if input.closed && w == nil || !input.methodBound || input.deadline == nil || !input.deadline.BelongsTo(s.config.Clock) || !h.HasExecutionIdentity() || h.IsResponse() {
		return ErrOwner
	}
	if w == nil {
		if input.borrowed {
			return ErrOwner
		}
	} else if !input.borrowed || w.input.generation != input.generation {
		return ErrOwner
	}
	if h.Kind() != "execution_unary_request" && h.Kind() != "execution_notify" && h.Kind() != "execution_stream_request" && h.Kind() != "resume_request" || p.Semantics != 1 || p.ExecutionMode != 1 || p.Checkpoint && !s.config.Store.SupportsCheckpoints() || p.RetainedContent && !s.config.Store.SupportsContent(p) {
		return ErrExecutionUnsupported
	}
	return input.reservation.Check()
}

func (s *DurableExecutions) entryLocked(routes *ContractRoutes, input *VerifiedInput, p protocolv4.ServiceContractPolicy) *contractRouteEntry {
	if routes.closed || routes.clock != s.config.Clock || p.Namespace != s.config.Service.Namespace {
		return nil
	}
	for i := range routes.entries {
		e := &routes.entries[i]
		if e.method == input.method && e.policy == p {
			return e
		}
	}
	return nil
}

func (s *DurableExecutions) checkVerified(target ExecutionTarget, access ExecutionAccess, routes *ContractRoutes, input *VerifiedInput, h protocolv4.ApplicationHeader, p protocolv4.ServiceContractPolicy, w *DurableExecutionWork) error {
	return access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		input.mu.Lock()
		defer input.mu.Unlock()
		if err := s.checkInputLocked(input, h, p, w); err != nil {
			return err
		}
		routes.mu.Lock()
		defer routes.mu.Unlock()
		e := s.entryLocked(routes, input, p)
		if e == nil || w != nil && (e != w.entry || !e.registered) {
			return ErrMethod
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		if err := s.reservation.CheckSameEnvironment(authority); err != nil {
			return err
		}
		return input.reservation.CheckSameEnvironment(s.reservation)
	})
}

func (s *DurableExecutions) reserveWorkLocked(response uint32) (refs [3]resourcev4.Reference, err error) {
	if response > 1048576 {
		return refs, ErrResponseLimit
	}
	work, err := durableExecutionWorkCharge(response, s.config.WorkRuntimeBytes)
	if err != nil {
		return refs, err
	}
	store, err := s.config.Store.WorkCharge()
	if err != nil {
		return refs, err
	}
	charges := [3]resourcev4.Vector{work, s.config.TaskCharge, store}
	s.serial++
	var seed [64]byte
	copy(seed[:23], "flowersec.durable/v4/")
	copy(seed[24:40], s.config.Owner.Instance[:])
	copy(seed[40:56], s.config.Owner.Backing[:])
	binary.BigEndian.PutUint64(seed[56:], s.serial)
	var requests [3]resourcev4.Request
	for i := range requests {
		seed[23] = byte(i)
		digest := sha256.Sum256(seed[:])
		owner := s.config.Owner
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[i] = resourcev4.Request{Owner: owner, Charge: charges[i], Accounts: s.config.Accounts}
	}
	err = s.config.Root.ReserveBatch(requests[:], refs[:])
	return
}

func (s *DurableExecutions) Close() {
	if s == nil || s.durableExecutions == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.reservation.Seal()
	count := len(s.works)
	s.mu.Unlock()
	for i := 0; i < count; i++ {
		s.mu.Lock()
		var w *DurableExecutionWork
		if i < len(s.works) {
			w = s.works[i]
		}
		s.mu.Unlock()
		if w != nil {
			w.cancel()
		}
	}
	for i := 0; i < count; i++ {
		s.mu.Lock()
		var floor *DurableExecutionAdmission
		if i < len(s.floors) {
			floor = s.floors[i]
		}
		s.mu.Unlock()
		if floor != nil {
			floor.Close()
		}
	}
	s.mu.Lock()
	s.cleanupLocked()
	s.mu.Unlock()
}

func (s *DurableExecutions) cleanupLocked() {
	if s.closed && s.active == 0 && s.calls == 0 && s.joins == 0 && s.floorCount == 0 && !s.cleaned {
		s.cleaned = true
		s.works = nil
		s.floors = nil
		s.storePin.Release()
		s.reservation.Release()
	}
}

func (s *DurableExecutions) CleanupComplete() bool {
	if s == nil || s.durableExecutions == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleaned
}

func (*DurableExecutions) String() string               { return "Flowersec.DurableExecutions" }
func (*DurableExecutions) GoString() string             { return "Flowersec.DurableExecutions" }
func (*DurableExecutions) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
