package rpcv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrExecutionConflict    = errors.New("rpcv4: operation conflict")
	ErrExecutionExpired     = errors.New("rpcv4: execution admission expired")
	ErrResultExpired        = errors.New("rpcv4: execution result expired")
	ErrResultUnavailable    = errors.New("rpcv4: execution result unavailable")
	ErrHistoryUnknown       = errors.New("rpcv4: execution history unknown")
	ErrExecutionUnsupported = errors.New("rpcv4: execution retention unavailable")
)

// ExecutionService is trusted local routing identity, not a received claim.
// One original service owner covers its Sessions and supported contracts.
type ExecutionService struct{ Tenant, Audience, Namespace string }
type ExecutionPrincipal struct {
	Authority [32]byte
	Subject   string
}
type ExecutionTarget struct {
	Service                                  ExecutionService
	Caller                                   ExecutionPrincipal
	Operation, RequestDigest, ContractDigest [32]byte
}

func (ExecutionTarget) String() string               { return "Flowersec.ExecutionTarget" }
func (ExecutionTarget) GoString() string             { return "Flowersec.ExecutionTarget" }
func (ExecutionTarget) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ExecutionAccess is an SDK authorization gate for the complete target. The
// actor may be an authorized administrator rather than the original caller.
// Implementations must perform only finite SDK work, never application code,
// I/O or store reentry. The reference pins its actual metadata through work.
type ExecutionAccess interface {
	WithExecutionAccess(ExecutionTarget, func(resourcev4.Reference) error) error
}

type ExecutionState uint8

const (
	ExecutionAccepted ExecutionState = iota + 1
	ExecutionExecuting
	ExecutionCompleted
	ExecutionFailed
	ExecutionUnknown
)

type ExecutionObservation struct {
	StreamMetadataOnly                      bool
	Found                                   bool
	State                                   ExecutionState
	CancelRequested, Dispatched, WorkActive bool
	HistoryNotBeforeGCMS, ResultNotAfterMS  uint64
	ResultAvailable, ResultDeleted          bool
	ResultBytes, ApplicationErrorCode       uint32
	ResultDigest                            [32]byte
	Reason                                  string
}
type ExecutionCancelResult struct {
	Kind        string
	Observation ExecutionObservation
}

// VolatileExecutionConfig is service-wide, never copied per Session. History
// and index backing is fully admitted at construction. Active executions are
// a subset of those records; each also admits real task/input/result owners.
type VolatileExecutionConfig struct {
	ContentMethods                                     []ContentMethod
	Root                                               *resourcev4.Root
	Owner                                              resourcev4.OwnerKey
	Accounts                                           []resourcev4.Account
	Clock                                              *timev4.Clock
	Service                                            ExecutionService
	CallerAuthorities                                  [][32]byte
	Records, Active                                    uint32
	TaskCharge                                         resourcev4.Vector
	RuntimeBytes, WorkRuntimeBytes, ResultRuntimeBytes uint64
}
type executionKey struct {
	operation [32]byte
	subject   [128]byte
	length    uint8
	domain    uint8
}
type executionDomain struct {
	authority [32]byte
	floor     uint64
}
type executionRecord struct {
	content                                     *executionContent
	streamMetadataOnly                          bool
	key                                         executionKey
	request, contract                           [32]byte
	state                                       ExecutionState
	used, dispatched, cancelRequested, signaled bool
	cancelMode                                  uint8
	generation, historyUntil                    uint64
	resultFormed, resultDeleted                 bool
	resultBytes, resultCode                     uint32
	resultDigest                                [32]byte
	resultExpires                               uint64
	reason                                      string
	work                                        *ExecutionWork
	result                                      *executionResult
	joins                                       uint32
}
type executionResult struct {
	reservation           resourcev4.Reference
	payload               []byte
	length, written, code uint32
	writeFailed           bool
	digest                [32]byte
	retentionMS, expires  uint64
	formed, expired       bool
	readers               uint32
}

// VolatileExecutions is the original live RAM authority. It cannot establish
// durable or replica-wide absence and never changes a request's identity.
// Collect is driven by the Environment's existing bounded coordinator.
type VolatileExecutions struct {
	contentMethods                       []ContentMethod
	mu                                   sync.Mutex
	root                                 *resourcev4.Root
	owner                                resourcev4.OwnerKey
	accounts                             [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                         int
	clock                                *timev4.Clock
	service                              ExecutionService
	domains                              []executionDomain
	records                              []executionRecord
	index                                []int32
	floors                               []*ExecutionAdmission
	floorCount                           uint32
	floorCursor                          int
	active, used, reserved, maxActive    uint32
	serial                               uint64
	cursor                               int
	taskCharge                           resourcev4.Vector
	workRuntimeBytes, resultRuntimeBytes uint64
	reservation                          resourcev4.Reference
	closed, cleaned                      bool
	continuities                         uint32
}

// ExecutionContinuity is an original local binding to this continuous owner.
// It is never serialized or reconstructed from a Session or imported reference.
// Absence without the same binding remains history_unknown.
type ExecutionContinuity struct{ capture *executionContinuityCapture }
type executionContinuityCapture struct {
	mu                   sync.Mutex
	owner                *VolatileExecutions
	reservation, backing resourcev4.Reference
}

func ExecutionContinuityCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(executionContinuityCapture{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// Continuity captures real local lifetime evidence. Copies share one release
// gate; closing any copy detaches every alias from the original store.
func (s *VolatileExecutions) Continuity(metadata resourcev4.Reference, runtimeBytes uint64) (ExecutionContinuity, error) {
	if s == nil {
		return ExecutionContinuity{}, ErrOwner
	}
	charge, err := ExecutionContinuityCharge(runtimeBytes)
	if err != nil {
		return ExecutionContinuity{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ExecutionContinuity{}, ErrClosed
	}
	if err := metadata.CheckSameEnvironment(s.reservation); err != nil {
		return ExecutionContinuity{}, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return ExecutionContinuity{}, err
	}
	backing, err := s.reservation.Borrow()
	if err != nil {
		owned.Release()
		return ExecutionContinuity{}, err
	}
	s.continuities++
	return ExecutionContinuity{&executionContinuityCapture{owner: s, reservation: owned, backing: backing}}, nil
}
func (c ExecutionContinuity) Close() {
	if c.capture == nil {
		return
	}
	x := c.capture
	x.mu.Lock()
	defer x.mu.Unlock()
	owner := x.owner
	x.owner = nil
	x.backing.Release()
	x.reservation.Release()
	x.backing, x.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	if owner != nil {
		owner.mu.Lock()
		if owner.continuities > 0 {
			owner.continuities--
		}
		owner.cleanupLocked()
		owner.mu.Unlock()
	}
}
func (ExecutionContinuity) String() string               { return "Flowersec.ExecutionContinuity" }
func (ExecutionContinuity) GoString() string             { return "Flowersec.ExecutionContinuity" }
func (ExecutionContinuity) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func executionIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || !strings.ContainsRune("._:/@-", rune(c)) {
			return false
		}
	}
	return true
}
func VolatileExecutionsCharge(c VolatileExecutionConfig) (resourcev4.Vector, error) {
	if err := validateContentMethods(c.ContentMethods); err != nil {
		return resourcev4.Vector{}, err
	}
	if c.Root == nil || c.Clock == nil || c.Records == 0 || c.Records > 65536 || c.Active == 0 || c.Active > c.Records || len(c.CallerAuthorities) == 0 || len(c.CallerAuthorities) > 128 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.RuntimeBytes == 0 || c.WorkRuntimeBytes == 0 || c.ResultRuntimeBytes == 0 || c.TaskCharge[resourcev4.Tasks] == 0 || c.TaskCharge[resourcev4.WorkSlots] == 0 || !executionIdentifier(c.Service.Tenant) || !executionIdentifier(c.Service.Audience) || !executionIdentifier(c.Service.Namespace) {
		return resourcev4.Vector{}, ErrConfiguration
	}
	for i, d := range c.CallerAuthorities {
		if d == ([32]byte{}) {
			return resourcev4.Vector{}, ErrConfiguration
		}
		for _, previous := range c.CallerAuthorities[:i] {
			if d == previous {
				return resourcev4.Vector{}, ErrConfiguration
			}
		}
	}
	n := uint64(unsafe.Sizeof(VolatileExecutions{})) + uint64(c.Records)*uint64(unsafe.Sizeof(executionRecord{})) + uint64(2*c.Records+1)*4 + uint64(len(c.CallerAuthorities))*uint64(unsafe.Sizeof(executionDomain{})) + uint64(len(c.Service.Tenant)+len(c.Service.Audience)+len(c.Service.Namespace))
	n += uint64(len(c.ContentMethods)) * uint64(unsafe.Sizeof(ContentMethod{}))
	n += uint64(c.Active) * uint64(unsafe.Sizeof((*ExecutionAdmission)(nil)))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1 + uint64(c.Records)}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}
func NewVolatileExecutions(c VolatileExecutionConfig, ref resourcev4.Reference) (*VolatileExecutions, error) {
	charge, err := VolatileExecutionsCharge(c)
	if err != nil {
		return nil, err
	}
	if err = ref.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	owned, err := ref.Take(charge)
	if err != nil {
		return nil, err
	}
	s := &VolatileExecutions{contentMethods: append([]ContentMethod(nil), c.ContentMethods...), root: c.Root, owner: c.Owner, clock: c.Clock, accountCount: len(c.Accounts), maxActive: c.Active, taskCharge: c.TaskCharge, workRuntimeBytes: c.WorkRuntimeBytes, resultRuntimeBytes: c.ResultRuntimeBytes, reservation: owned, records: make([]executionRecord, c.Records), index: make([]int32, 2*c.Records+1), domains: make([]executionDomain, len(c.CallerAuthorities))}
	s.service = ExecutionService{strings.Clone(c.Service.Tenant), strings.Clone(c.Service.Audience), strings.Clone(c.Service.Namespace)}
	s.floors = make([]*ExecutionAdmission, c.Active)
	copy(s.accounts[:], c.Accounts)
	for i, d := range c.CallerAuthorities {
		s.domains[i].authority = d
	}
	for i := range s.index {
		s.index[i] = -1
	}
	return s, nil
}
func (*VolatileExecutions) String() string               { return "Flowersec.VolatileExecutions" }
func (*VolatileExecutions) GoString() string             { return "Flowersec.VolatileExecutions" }
func (*VolatileExecutions) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (s *VolatileExecutions) keyLocked(target ExecutionTarget) (executionKey, error) {
	if target.Service != s.service || !executionIdentifier(target.Caller.Subject) {
		return executionKey{}, ErrAssociation
	}
	for i, d := range s.domains {
		if d.authority != target.Caller.Authority {
			continue
		}
		k := executionKey{operation: target.Operation, length: uint8(len(target.Caller.Subject)), domain: uint8(i)}
		// Length 128 is represented exactly by uint8, not a sentinel.
		copy(k.subject[:], target.Caller.Subject)
		return k, nil
	}
	return executionKey{}, ErrAssociation
}
func (s *VolatileExecutions) findLocked(k executionKey) (record, bucket int) {
	var b [162]byte
	copy(b[:32], k.operation[:])
	copy(b[32:160], k.subject[:])
	b[160], b[161] = k.length, k.domain
	h := sha256.Sum256(b[:])
	start := binary.BigEndian.Uint64(h[:8]) % uint64(len(s.index))
	free := -1
	for n := 0; n < len(s.index); n++ {
		i := int((start + uint64(n)) % uint64(len(s.index)))
		x := s.index[i]
		if x == -1 {
			if free < 0 {
				free = i
			}
			return -1, free
		}
		if x == -2 {
			if free < 0 {
				free = i
			}
			continue
		}
		if s.records[x].key == k {
			return int(x), i
		}
	}
	return -1, free
}
func (s *VolatileExecutions) targetLocked(r *executionRecord) ExecutionTarget {
	return ExecutionTarget{Service: s.service, Caller: ExecutionPrincipal{s.domains[r.key.domain].authority, string(r.key.subject[:r.key.length])}, Operation: r.key.operation, RequestDigest: r.request, ContractDigest: r.contract}
}
func (s *VolatileExecutions) snapshotLocked(r *executionRecord) ExecutionObservation {
	v := ExecutionObservation{StreamMetadataOnly: r.streamMetadataOnly, ApplicationErrorCode: r.resultCode, Found: true, State: r.state, CancelRequested: r.cancelRequested, Dispatched: r.dispatched, WorkActive: r.work != nil, HistoryNotBeforeGCMS: r.historyUntil, Reason: r.reason}
	if r.resultFormed {
		v.ResultNotAfterMS = r.resultExpires
		if r.result != nil && !r.result.expired && !s.closed {
			now, err := s.clock.Sample()
			v.ResultAvailable = err == nil && now.ValidBefore(r.resultExpires)
		}
		v.ResultDeleted = r.resultDeleted
		v.ResultBytes = r.resultBytes
		v.ApplicationErrorCode = r.resultCode
		v.ResultDigest = r.resultDigest
	}
	return v
}

// Admit accepts only genuine fully verified execution input and its original
// exact registered route. The supplied caller comes from trusted identity
// mapping; access rechecks that complete target before lookup can reveal it.
// Existing records join before applying a new Offer, horizon or capacity limit.
// Streaming content/checkpoint and durable stores require their own real
// retention adapter; this RAM implementation refuses those obligations.
func (s *VolatileExecutions) Admit(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess) (ExecutionObservation, *ExecutionWork, error) {
	return s.admit(ctx, routes, input, caller, access, nil, nil, nil)
}

// AdmitForDispatch acquires the actual ordinary execution position inside the
// original admission decision, before a new operation is registered. Existing
// operations never invoke reserve and cannot acquire another dispatch right.
func (s *VolatileExecutions) AdmitForDispatch(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, reserve func(resourcev4.Reference, resourcev4.Reference) error) (ExecutionObservation, *ExecutionWork, error) {
	if reserve == nil {
		return ExecutionObservation{}, nil, ErrConfiguration
	}
	return s.admit(ctx, routes, input, caller, access, reserve, nil, nil)
}

func (s *VolatileExecutions) admit(ctx context.Context, routes *ContractRoutes, input *VerifiedInput, caller ExecutionPrincipal, access ExecutionAccess, reserve func(resourcev4.Reference, resourcev4.Reference) error, join *ExecutionJoin, admission *ExecutionAdmission) (observation ExecutionObservation, work *ExecutionWork, err error) {
	if s == nil || ctx == nil || routes == nil || input == nil || access == nil {
		return observation, nil, ErrConfiguration
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return observation, nil, ErrClosed
	}
	clock, service := s.clock, s.service
	var pin resourcev4.Reference
	if admission == nil {
		pin, err = s.reservation.Borrow()
	} else {
		pin = admission.historyPin
		err = pin.Check()
	}
	s.mu.Unlock()
	if err != nil {
		return observation, nil, err
	}
	if admission == nil {
		defer pin.Release()
	}
	input.mu.Lock()
	h, policy := input.header, input.policy
	input.mu.Unlock()
	target := ExecutionTarget{Service: service, Caller: caller, Operation: h.Fields().OperationID, RequestDigest: h.Fields().RequestDigest, ContractDigest: h.Fields().ServiceContractDigest}
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		if admission != nil && (authority != admission.authority || h.Kind() != "execution_unary_request" || h.Fields().ResponseLimitBytes > admission.maxResponse) {
			return ErrOwner
		}
		input.mu.Lock()
		defer input.mu.Unlock()
		if input.header != h || input.policy != policy {
			return ErrAssociation
		}
		if input.closed || input.borrowed || !input.methodBound || !input.header.HasExecutionIdentity() || input.header.IsResponse() || input.deadline == nil || !input.deadline.BelongsTo(clock) {
			return ErrOwner
		}
		if err = input.reservation.CheckSameEnvironment(pin); err != nil {
			return err
		}
		// Recovery variants need their own checkpoint/token consumption gate.
		if h.Kind() != "execution_unary_request" && h.Kind() != "execution_notify" && h.Kind() != "execution_stream_request" {
			return ErrExecutionUnsupported
		}
		routes.mu.Lock()
		defer routes.mu.Unlock()
		if routes.closed || routes.clock != clock {
			return ErrClosed
		}
		var entry *contractRouteEntry
		for i := range routes.entries {
			if routes.entries[i].method == input.method && routes.entries[i].policy == policy && routes.entries[i].registered {
				entry = &routes.entries[i]
				break
			}
		}
		if entry == nil || policy.Namespace != service.Namespace {
			return ErrMethod
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.reservation.CheckSameEnvironment(authority); err != nil {
			return err
		}
		key, err := s.keyLocked(target)
		if err != nil {
			return err
		}
		index, bucket := s.findLocked(key)
		if index >= 0 {
			r := &s.records[index]
			if r.request != target.RequestDigest || r.contract != target.ContractDigest {
				return ErrExecutionConflict
			}
			if join != nil {
				if err := join.prepareLocked(s, authority, admission); err != nil {
					return err
				}
				if r.joins == math.MaxUint32 || r.result != nil && r.result.readers == math.MaxUint32 {
					return ErrCapacity
				}
				join.attachLocked(s, index, target, access)
			}
			observation = s.snapshotLocked(r)
			return nil
		}
		if policy.Semantics != 1 || policy.ExecutionMode != 0 || policy.Checkpoint || policy.RetainedContent && !s.supportsContent(policy) {
			return ErrExecutionUnsupported
		}
		now, err := input.deadline.Sample()
		if err != nil {
			return err
		}
		cutoff := binary.BigEndian.Uint64(key.operation[:8])
		deadline := h.Fields().DeadlineAtMS
		if cutoff <= s.domains[key.domain].floor || policy.AdmissionWindowMS == 0 || policy.ExecutionHorizonMS == 0 || policy.ExecutionRunMS == 0 || policy.HistoryRetentionMS == 0 || policy.AdmissionWindowMS > math.MaxUint64-now.LowerMS || policy.ExecutionHorizonMS > math.MaxUint64-now.LowerMS || cutoff <= now.UpperMS || cutoff > now.LowerMS+policy.AdmissionWindowMS || deadline <= now.UpperMS || deadline > now.LowerMS+policy.ExecutionHorizonMS || policy.HistoryRetentionMS > math.MaxUint64-deadline {
			return ErrExecutionExpired
		}
		if policy.RetainedContent && policy.Content.RetentionMS > math.MaxUint64-now.UpperMS {
			return ErrConfiguration
		}
		if _, ok := usableOffer(entry, now, cutoff, false); !ok {
			return ErrExecutionExpired
		}
		s.refreshAdmissionFloorsLocked()
		reserved := s.reserved
		if admission != nil {
			reserved--
		}
		if s.used+reserved == uint32(len(s.records)) || s.active+reserved == s.maxActive || bucket < 0 || s.serial == math.MaxUint64 || routes.captures == math.MaxUint32 || input.generation == math.MaxUint64 {
			return ErrCapacity
		}
		for i := range s.records {
			if !s.records[i].used && s.records[i].generation < math.MaxUint64 {
				index = i
				break
			}
		}
		if index < 0 {
			return ErrCapacity
		}
		if err := s.reservation.CheckSameEnvironment(authority); err != nil {
			return err
		}
		if join != nil {
			if err := join.prepareLocked(s, authority, admission); err != nil {
				return err
			}
		}
		var refs [3]resourcev4.Reference
		if admission == nil {
			refs, err = s.reserveWorkLocked(h, policy)
		} else {
			refs, err = admission.takeWorkLocked(s, h.Fields().ResponseLimitBytes)
		}
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				for _, ref := range refs {
					ref.Release()
				}
			}
		}()
		var borrow resourcev4.Reference
		if admission == nil {
			borrow, err = authority.Borrow()
		} else {
			borrow = admission.workAuthority
			if !admission.reusable {
				admission.workAuthority = resourcev4.Reference{}
			}
			err = borrow.Check()
		}
		if err != nil {
			releaseExecutionAuthority(borrow, admission)
			return err
		}
		fixed, err := input.deadline.Fork(deadline)
		if err != nil {
			releaseExecutionAuthority(borrow, admission)
			return err
		}
		if reserve != nil {
			if err = reserve(refs[1], refs[0]); err != nil {
				releaseExecutionAuthority(borrow, admission)
				return err
			}
		}
		input.generation++
		input.borrowed = true
		r := &s.records[index]
		generation := r.generation + 1
		*r = executionRecord{streamMetadataOnly: policy.Shape == 1, key: key, request: target.RequestDigest, contract: target.ContractDigest, state: ExecutionAccepted, used: true, generation: generation, historyUntil: deadline + policy.HistoryRetentionMS, cancelMode: policy.CancelMode}
		target.Caller.Subject = strings.Clone(target.Caller.Subject)
		work = &ExecutionWork{history: s, index: index, generation: generation, input: InputBorrow{input, input.generation}, routes: routes, entry: entry, access: access, target: target, deadline: fixed, runMS: executionRunLimit(policy), reservation: refs[0], task: refs[1], authority: borrow, cancelled: make(chan struct{})}
		if admission != nil && admission.reusable {
			work.admission = admission
			admission.tails.Add(1)
		}
		if policy.Shape == 0 {
			r.result = &executionResult{reservation: refs[2], payload: make([]byte, h.Fields().ResponseLimitBytes), retentionMS: policy.ResultRetentionMS}
		}
		if policy.RetainedContent {
			r.content = &executionContent{reservation: refs[2], policy: policy.Content, readType: s.ContentReadType(policy.Type), admitted: now.UpperMS, items: make([]executionContentItem, policy.Content.MaxItems), payload: make([]byte, policy.Content.MaxBytes)}
		}
		r.work = work
		if join != nil {
			join.attachLocked(s, index, target, access)
		}
		s.index[bucket] = int32(index)
		if admission != nil {
			admission.consumeLocked(s)
		}
		s.used++
		s.active++
		routes.captures++
		observation = s.snapshotLocked(r)
		return nil
	})
	return observation, work, err
}

func executionWorkCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ExecutionWork{})) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})) + 128, resourcev4.Items: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func (s *VolatileExecutions) workChargesLocked(response uint32, result bool) (charges [3]resourcev4.Vector, err error) {
	charges[0], err = executionWorkCharge(s.workRuntimeBytes)
	if err != nil {
		return charges, err
	}
	charges[1] = s.taskCharge
	if result {
		charges[2], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(executionResult{})) + uint64(response), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: s.resultRuntimeBytes})
	}
	return
}

func (s *VolatileExecutions) reserveWorkLocked(h protocolv4.ApplicationHeader, p protocolv4.ServiceContractPolicy) (refs [3]resourcev4.Reference, err error) {
	charges, err := s.workChargesLocked(h.Fields().ResponseLimitBytes, p.Shape == 0)
	if err != nil {
		return refs, err
	}
	count := 2
	if p.Shape == 0 {
		count = 3
	}
	if p.RetainedContent {
		charges[2], err = executionContentCharge(p.Content)
		if err != nil {
			return refs, err
		}
		count = 3
	}
	s.serial++
	var requests [3]resourcev4.Request
	var seed [64]byte
	copy(seed[:23], "flowersec.execution/v4/")
	copy(seed[24:40], s.owner.Instance[:])
	copy(seed[40:56], s.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[56:], s.serial)
	for i := range count {
		seed[23] = byte(i)
		digest := sha256.Sum256(seed[:])
		owner := s.owner
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[i] = resourcev4.Request{Owner: owner, Charge: charges[i], Accounts: s.accounts[:s.accountCount]}
	}
	err = s.root.ReserveBatch(requests[:count], refs[:count])
	return
}

func (s *VolatileExecutions) observe(target ExecutionTarget, continuity ExecutionContinuity, access ExecutionAccess, cancel bool) (observation ExecutionObservation, kind string, err error) {
	if s == nil || access == nil {
		return observation, "", ErrConfiguration
	}
	var original *VolatileExecutions
	if c := continuity.capture; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		original = c.owner
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
		key, err := s.keyLocked(target)
		if err != nil {
			return err
		}
		i, _ := s.findLocked(key)
		if i < 0 {
			kind = "history_unknown"
			if original == s && binary.BigEndian.Uint64(key.operation[:8]) > s.domains[key.domain].floor {
				kind = "not_registered"
			}
			observation.Reason = kind
			return nil
		}
		r := &s.records[i]
		if r.request != target.RequestDigest || r.contract != target.ContractDigest {
			return ErrExecutionConflict
		}
		kind = "terminal"
		if cancel {
			if r.cancelMode != 1 {
				return ErrExecutionUnsupported
			}
			if r.state == ExecutionAccepted || r.state == ExecutionExecuting || r.state == ExecutionUnknown {
				r.cancelRequested = true
				kind = "requested"
				s.signalLocked(r)
				if !r.dispatched {
					r.state = ExecutionFailed
					r.reason = "cancelled"
				}
			}
		}
		observation = s.snapshotLocked(r)
		return nil
	})
	return
}
func (s *VolatileExecutions) Query(target ExecutionTarget, continuity ExecutionContinuity, access ExecutionAccess) (ExecutionObservation, error) {
	v, _, err := s.observe(target, continuity, access, false)
	return v, err
}
func (s *VolatileExecutions) RequestCancel(target ExecutionTarget, continuity ExecutionContinuity, access ExecutionAccess) (ExecutionCancelResult, error) {
	v, kind, err := s.observe(target, continuity, access, true)
	return ExecutionCancelResult{Kind: kind, Observation: v}, err
}
func (s *VolatileExecutions) signalLocked(r *executionRecord) {
	if r.work != nil && !r.signaled {
		r.signaled = true
		close(r.work.cancelled)
		if r.work.cancelContext != nil {
			r.work.cancelContext()
		}
	}
}

// Collect performs at most 64 record transitions per call. A floor advances
// only from this owner's trusted lower bound, before any covered detail is
// removed. Real work and retained result readers prevent physical reclamation.
func (s *VolatileExecutions) Collect() error {
	if s == nil {
		return ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned {
		return nil
	}
	now, err := s.clock.Sample()
	if err == nil {
		for i := range s.domains {
			s.domains[i].floor = max(s.domains[i].floor, now.LowerMS)
		}
	}
	for range min(64, len(s.records)) {
		i := s.cursor
		s.cursor = (s.cursor + 1) % len(s.records)
		r := &s.records[i]
		if !r.used {
			continue
		}
		if err != nil {
			if r.work != nil {
				s.signalLocked(r)
				if r.state == ExecutionAccepted || r.state == ExecutionExecuting {
					r.state = ExecutionUnknown
					r.reason = "work_outcome_unknown"
				}
			}
			// Unavailable time never advances an absence floor or expires history.
			continue
		}
		if r.work != nil {
			if r.work.deadline.CheckAt(now) != nil || r.work.run != nil && r.work.run.CheckAt(now) != nil {
				s.signalLocked(r)
				if r.state == ExecutionAccepted || r.state == ExecutionExecuting {
					r.state = ExecutionUnknown
					r.reason = "deadline_exceeded"
				}
			}
		}
		if b := r.result; b != nil && b.formed && b.retentionMS != 0 && now.LowerMS >= b.expires {
			b.expired = true
			s.cleanupResultLocked(r)
		}
		if r.content != nil && now.LowerMS < r.content.latestExpiry {
			continue
		}
		if r.work != nil || r.result != nil || r.joins != 0 || now.LowerMS < r.historyUntil || binary.BigEndian.Uint64(r.key.operation[:8]) > s.domains[r.key.domain].floor {
			continue
		}
		s.removeLocked(i)
	}
	s.refreshAdmissionFloorsLocked()
	s.cleanupLocked()
	return err
}
func (s *VolatileExecutions) cleanupResultLocked(r *executionRecord) {
	b := r.result
	if b == nil || !b.expired || b.readers != 0 {
		return
	}
	clear(b.payload)
	b.payload = nil
	b.reservation.Release()
	b.reservation = resourcev4.Reference{}
	r.result = nil
	r.resultDeleted = r.resultFormed
}
func (s *VolatileExecutions) removeLocked(i int) {
	r := &s.records[i]
	_, bucket := s.findLocked(r.key)
	if bucket >= 0 {
		s.index[bucket] = -2
	}
	r.content.close()
	generation := r.generation
	*r = executionRecord{generation: generation}
	s.used--
}
func (s *VolatileExecutions) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for i := range s.records {
		r := &s.records[i]
		if !r.used {
			continue
		}
		s.signalLocked(r)
		if r.result != nil {
			r.result.expired = true
			s.cleanupResultLocked(r)
		}
		if r.work == nil && r.result == nil && r.joins == 0 {
			s.removeLocked(i)
		}
	}
	s.cleanupLocked()
}
func (s *VolatileExecutions) cleanupLocked() {
	if !s.closed || s.cleaned || s.used != 0 || s.reserved != 0 || s.floorCount != 0 || s.continuities != 0 {
		return
	}
	s.records = nil
	s.floors = nil
	s.index = nil
	s.domains = nil
	s.service = ExecutionService{}
	s.root = nil
	s.clock = nil
	clear(s.accounts[:])
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	s.cleaned = true
}
func (s *VolatileExecutions) CleanupComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleaned
}
