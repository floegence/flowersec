package sessionv4

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ContractQueryMethod fixes the finite local authorization lookup before
// admission. This is not a remote directory or permission supplied by a peer.
type ContractQueryMethod struct {
	Namespace string
	Type      uint32
}

type queryMethodAccess struct {
	method ContractQueryMethod
	access rpcv4.QueryTargetAccess
}

func sessionContractQueriesCharge(c SessionPlanConfig) (resourcev4.Vector, error) {
	if !c.ContractQueries {
		if len(c.ContractQueryMethods) != 0 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		return resourcev4.Vector{}, nil
	}
	if len(c.ContractQueryMethods) > 128 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	var scratch [512]byte
	for i, method := range c.ContractQueryMethods {
		if method.Type == 0 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		if _, err := protocolv4.EncodeMap(scratch[:], "ContractTarget", []protocolv4.Field{{Name: "service_namespace", Kind: protocolv4.TextString, Text: method.Namespace}, {Name: "method_type_id", Number: uint64(method.Type)}}); err != nil {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for _, earlier := range c.ContractQueryMethods[:i] {
			if earlier == method {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(sessionContractQueries{})) + uint64(len(c.ContractQueryMethods))*(uint64(unsafe.Sizeof(queryMethodAccess{}))+128), resourcev4.Items: uint64(len(c.ContractQueryMethods)) + 1}, nil
}

func (p *SessionPlan) initializeContractQueryMethods(methods []ContractQueryMethod) {
	p.config.ContractQueryMethods = nil
	p.lease.queryMethods = make([]queryMethodAccess, len(methods))
	p.lease.queryEpoch = 1
	for i, method := range methods {
		p.lease.queryMethods[i].method = ContractQueryMethod{strings.Clone(method.Namespace), method.Type}
	}
}

// SetContractQueryAccess updates only this original authenticated lease's
// predeclared method. The trusted host calls it from its own authorization
// lifecycle; the fixed worker never invokes a user hook or waits for its I/O.
// Unknown source state is unavailable by default, and absent methods are denied.
// This handle grants no execution permit and cannot outlive lease revocation.
func (l *ApplicationLease) SetContractQueryAccess(method ContractQueryMethod, access rpcv4.QueryTargetAccess) error {
	if l == nil || access > rpcv4.QueryTargetAllowed {
		return ErrApplicationAuthorization
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || l.revoked {
		return ErrApplicationAuthorization
	}
	for i := range l.queryMethods {
		entry := &l.queryMethods[i]
		if entry.method != method {
			continue
		}
		if entry.access == access {
			return nil
		}
		if l.queryEpoch == math.MaxUint64 {
			return cryptov4.ErrCapacity
		}
		l.queryEpoch++
		entry.access = access
		return nil
	}
	return ErrApplicationAuthorization
}

func (p *SessionPlan) queryAuthorization() (*ApplicationLease, *protocolv4.EndpointAuthorization, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.authorized {
		return nil, nil, ErrApplicationAuthorization
	}
	if err := p.reservation.Check(); err != nil {
		return nil, nil, err
	}
	if err := p.dependencies.Check(); err != nil {
		return nil, nil, err
	}
	l := p.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || !l.authorized || l.revoked || l.authorization == nil {
		return nil, nil, ErrApplicationAuthorization
	}
	return l, l.authorization, nil
}

func (p *SessionPlan) queryAccess(target protocolv4.ContractQueryTarget) (rpcv4.QueryTargetAccess, uint64, error) {
	l, a, err := p.queryAuthorization()
	if err != nil {
		return rpcv4.QueryTargetUnavailable, 0, err
	}
	if err := a.Check(); err != nil {
		return rpcv4.QueryTargetUnavailable, 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked || l.authorization != a {
		return rpcv4.QueryTargetDenied, 0, ErrApplicationAuthorization
	}
	for _, entry := range l.queryMethods {
		if entry.method.Namespace == target.Namespace && entry.method.Type == target.Type {
			return entry.access, l.queryEpoch, nil
		}
	}
	return rpcv4.QueryTargetDenied, l.queryEpoch, nil
}

// The original lease gate orders target-policy changes with complete response
// publication. Endpoint checks are SDK-only and occur outside the lease gate.
// The publication itself runs only fixed codecs and local original owner gates.
func (p *SessionPlan) publishContractQuery(job rpcv4.ContractQueryJob, epoch uint64) error {
	l, a, err := p.queryAuthorization()
	if err != nil {
		return err
	}
	if err := a.Check(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked || l.authorization != a || epoch == 0 || l.queryEpoch != epoch {
		return ErrApplicationAuthorization
	}
	return job.Publish()
}

type sessionContractQueries struct {
	service       *rpcv4.ContractQueryService
	consumer      atomic.Pointer[rpcv4.ContractQueryConsumer]
	initiator     atomic.Pointer[rpcv4.ContractQueryInitiator]
	workers       atomic.Int32
	group         sdkQueryGroup
	registrations [2]*sdkQueryRegistration
	owners        [2]incomingSDKQuery
}

// InstallContractQueries is a once-only pre-admission attachment. Both incoming
// positions share the original root executor and one Session query service.
// Failed installation leaves the plan unusable for queries; Close/Retire joins
// any already captured index references. It never allocates a Session worker.
func (p *SessionPlan) InstallContractQueries(service *rpcv4.ContractQueryService) error {
	if p == nil || service == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.queries != nil || !p.config.ContractQueries {
		return cryptov4.ErrTransition
	}
	if p.services != nil {
		if err := p.services.network.CheckQueryService(service); err != nil {
			return err
		}
	}
	x := &sessionContractQueries{service: service}
	x.workers.Store(2)
	p.queries = x
	for i := range x.owners {
		x.owners[i] = incomingSDKQuery{parent: x, plan: p}
		borrow, err := p.reservation.Borrow()
		if err != nil {
			x.close()
			return err
		}
		r, err := p.executor.registerSDKQuery(&x.group, 0, &x.owners[i], borrow)
		borrow.Release()
		if err != nil {
			x.close()
			return err
		}
		x.registrations[i] = r
	}
	consumer, err := service.ClaimConsumer(p.executor.queries.sourceWake, p.reservation)
	if err != nil {
		x.close()
		return err
	}
	x.consumer.Store(consumer)
	if err := p.checkQueryAttachmentLocked(false); err != nil {
		x.consumer.Swap(nil).Stop()
		x.close()
		return err
	}
	for _, r := range x.registrations {
		r.Wake()
	}
	return nil
}

func (p *SessionPlan) checkContractQueriesLocked() error { return p.checkQueryAttachmentLocked(true) }
func (p *SessionPlan) checkQueryAttachmentLocked(requireOutgoing bool) error {
	if !p.config.ContractQueries {
		return nil
	}
	if p.queries == nil || p.queries.consumer.Load() == nil || p.queries.workers.Load() != 2 {
		return cryptov4.ErrConfiguration
	}
	if requireOutgoing && p.queries.initiator.Load() == nil {
		return cryptov4.ErrConfiguration
	}
	for _, r := range p.queries.registrations {
		if r == nil || r.executor.Load() != p.executor {
			return cryptov4.ErrConfiguration
		}
	}
	snapshot := p.executor.Snapshot()
	if snapshot.Closed || snapshot.QueryFailed {
		return cryptov4.ErrClosed
	}
	return nil
}

func (x *sessionContractQueries) close() {
	x.initiator.Swap(nil).Stop()
	for _, r := range x.registrations {
		r.Close()
	}
}

func (x *sessionContractQueries) wait(ctx context.Context) error {
	for _, r := range x.registrations {
		if r == nil {
			continue
		}
		select {
		case <-r.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (x *sessionContractQueries) complete() bool {
	for _, r := range x.registrations {
		if r == nil {
			continue
		}
		select {
		case <-r.done:
		default:
			return false
		}
	}
	return true
}

type incomingSDKQuery struct {
	parent *sessionContractQueries
	plan   *SessionPlan
	job    rpcv4.ContractQueryJob
	epoch  uint64
	phase  uint8
}

func (w *incomingSDKQuery) queryStep() (bool, error) {
	if w.phase == 0 {
		consumer := w.parent.consumer.Load()
		if consumer == nil {
			return false, nil
		}
		if n, err := consumer.RefuseExpired(); err != nil && !errors.Is(err, rpcv4.ErrCapacity) {
			return false, err
		} else if n != 0 {
			return true, nil
		}
		job, err := consumer.Begin()
		if errors.Is(err, rpcv4.ErrCapacity) {
			return false, nil
		}
		if errors.Is(err, rpcv4.ErrContractQuerySchema) {
			return true, nil // Only the original channel was failed.
		}
		if err != nil {
			return false, err
		}
		w.job, w.phase = job, 1
		return true, nil
	}
	var err error
	switch w.phase {
	case 1:
		index, target, nextErr := w.job.NextTarget()
		if errors.Is(nextErr, rpcv4.ErrCapacity) {
			w.phase = 2
			return true, nil
		}
		err = nextErr
		if err == nil {
			var access rpcv4.QueryTargetAccess
			var epoch uint64
			access, epoch, err = w.plan.queryAccess(target)
			if err == nil && w.epoch != 0 && w.epoch != epoch {
				err = ErrApplicationAuthorization
			}
			if err == nil {
				w.epoch = epoch
				err = w.job.Resolve(index, access)
			}
		}
	case 2:
		var done bool
		done, err = w.job.EncodeStep()
		if done {
			w.phase = 3
		}
	case 3:
		err = w.plan.publishContractQuery(w.job, w.epoch)
		if err == nil {
			w.clearJob()
		}
	}
	if err != nil {
		code := "service_unavailable"
		if errors.Is(err, timev4.ErrExpired) {
			code = "deadline_exceeded"
		} else if errors.Is(err, ErrApplicationAuthorization) {
			code = "permission_denied"
		}
		_ = w.job.Refuse(code)
		w.clearJob()
	}
	return true, nil
}

func (w *incomingSDKQuery) clearJob() {
	w.job.Close()
	w.job, w.epoch, w.phase = rpcv4.ContractQueryJob{}, 0, 0
}

func (w *incomingSDKQuery) queryClose() {
	if w.phase != 0 {
		_ = w.job.Refuse("service_unavailable")
		w.clearJob()
	}
	if w.parent.workers.Add(-1) == 0 {
		w.parent.consumer.Swap(nil).Stop()
	}
	w.parent, w.plan = nil, nil
}

// InstallOutgoingContractQueries captures the same Session network's Q2 owner
// before admission. All starts after this point require its Environment owner.
func (p *SessionPlan) InstallOutgoingContractQueries(client *rpcv4.ContractQueryClient) error {
	if p == nil || client == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.queries == nil || p.queries.initiator.Load() != nil {
		return cryptov4.ErrTransition
	}
	if err := client.CheckService(p.queries.service); err != nil {
		return err
	}
	x, err := client.ClaimInitiator(p.executor.queries.sourceWake, p.reservation)
	if err != nil {
		return err
	}
	p.queries.initiator.Store(x)
	return nil
}
