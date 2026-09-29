package controlv4

import (
	"context"
	"strings"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func (h *LiveArtifactHost) CheckLiveAuthorizationShare(identity ledgerv4.SQLiteIdentity, rate, burst uint16) error {
	if h == nil {
		return resourcev4.ErrOwner
	}
	h.mu.Lock()
	if err := h.checkLocked(); err != nil {
		h.mu.Unlock()
		return err
	}
	if h.operations != 0 {
		h.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	h.operations++
	policy := h.template.config.Policy
	h.mu.Unlock()
	defer func() { h.mu.Lock(); h.operations--; h.mu.Unlock(); h.collect(nil) }()
	if err := liveArtifactCall(func() error { return policy.CheckLiveAuthorizationShare(identity, rate, burst) }); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checkLocked()
}

func (h *LiveArtifactHost) AcquireLiveAuthorization(ctx context.Context, client [32]byte, q sessionv4.LiveAuthorizationRequest) (_ LiveAuthorizationAccess, err error) {
	if h == nil || ctx == nil || checkLiveRequest(q) != nil {
		return nil, resourcev4.ErrConfiguration
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	if err = h.checkLocked(); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	if client != h.template.config.ClientCertificateDigest {
		h.mu.Unlock()
		return nil, ledgerv4.ErrDenied
	}
	index := -1
	for i := range h.slots {
		s := &h.slots[i]
		if s.request != ([32]byte{}) && s.facts.Scope.Tenant == q.Tenant && s.facts.Scope.Issuer == q.Issuer && s.facts.LeaseID == q.Lease {
			index = i
			break
		}
	}
	if index < 0 {
		h.mu.Unlock()
		return nil, ledgerv4.ErrDenied
	}
	s := &h.slots[index]
	if s.issuing || s.working || s.access || s.retiring || !s.ready || s.failed {
		h.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	f := s.facts
	if q.Audience != f.Scope.Audience || q.CryptoProfile != f.Scope.Profile || q.ClientIdentity != f.ClientIdentity || q.ServerIdentity != f.ServerIdentity || q.Artifact != s.credential.Facts().Digest || q.ActivationNotAfterMS > f.InitiationNotAfterMS || s.frozen && q != s.query {
		h.mu.Unlock()
		return nil, ledgerv4.ErrConflict
	}
	s.working = true
	first := s.plan == nil
	if !s.frozen {
		q.Tenant, q.Audience, q.CryptoProfile = strings.Clone(q.Tenant), strings.Clone(q.Audience), strings.Clone(q.CryptoProfile)
		s.query, s.frozen = q, true
	}
	generation := s.generation
	h.mu.Unlock()
	adopted := false
	defer func() {
		if recover() != nil {
			err = sessionv4.ErrEnvironmentTaskExit
		}
		h.mu.Lock()
		s.working = false
		if !adopted && first && s.constructionStarted {
			s.failed = true
		}
		h.mu.Unlock()
		h.collect(nil)
	}()
	if err = h.checkIssue(ctx, s); err != nil {
		return nil, err
	}
	if first {
		if err = s.deadline.Tighten(q.ActivationNotAfterMS); err != nil {
			return nil, err
		}
		if err = h.template.validateMaterial(s.artifact, s.credential, h.reservation); err != nil {
			return nil, err
		}
		h.mu.Lock()
		s.constructionStarted = true
		h.mu.Unlock()
		planReservation, e := s.planWork.Checkout()
		if e != nil {
			return nil, e
		}
		defer planReservation.Release()
		s.plan, err = h.template.buildPlan(s.artifact, s.credential, q, planReservation, h.reservation)
		// A successful plan adopted the reservation's generation. Release only
		// returns an unadopted original reference after constructor failure.
		planReservation.Release()
		if err != nil {
			return nil, err
		}
		s.fields, _, err = s.plan.CopyProjection(s.projection)
		clear(s.projection)
		if err != nil {
			return nil, err
		}
		p := s.fields
		if p.Tenant != q.Tenant || p.Audience != q.Audience || p.Profile != q.CryptoProfile || p.Issuer != q.Issuer || p.Lease != q.Lease || p.Artifact != q.Artifact || p.ClientIdentity != q.ClientIdentity || p.ServerIdentity != q.ServerIdentity || p.Attempt != q.Attempt || p.Winner != q.Winner || p.ActivationEnd != q.ActivationNotAfterMS {
			return nil, ledgerv4.ErrConflict
		}
		if p.Tunnel {
			resolver := h.template.config.Tunnels[q.Winner.Index].Server
			material, e := h.template.serverMaterial(s.artifact, s.credential, q.Winner.Index, h.reservation)
			if e != nil {
				return nil, e
			}
			s.server, err = resolver.PrepareLiveServerAllow(ctx, p, material)
			if err != nil {
				return nil, err
			}
			if s.server == nil {
				return nil, resourcev4.ErrConfiguration
			}
			s.serverAllow, err = s.server.Configuration()
			if err != nil {
				return nil, err
			}
			if _, err = s.serverAllow.Request(s.plan, p, s.deadline.Cap()); err != nil {
				return nil, err
			}
		}
	}
	if err = h.checkIssue(ctx, s); err != nil {
		return nil, err
	}
	if s.server != nil {
		if err = liveArtifactCall(func() error { return s.server.Check(ctx) }); err != nil {
			return nil, err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err = h.checkLocked(); err != nil {
		return nil, err
	}
	s.access = true
	adopted = true
	return &retainedLiveAccess{host: h, index: index, generation: generation, done: make(chan struct{})}, nil
}

type retainedLiveAccess struct {
	mu                       sync.Mutex
	host                     *LiveArtifactHost
	index                    int
	generation               uint64
	done                     chan struct{}
	active, closed, released bool
}

func (a *retainedLiveAccess) begin() (*LiveArtifactHost, *liveArtifactSlot, error) {
	if a == nil {
		return nil, nil, resourcev4.ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.active {
		return nil, nil, resourcev4.ErrOwner
	}
	h := a.host
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.checkLocked(); err != nil {
		return nil, nil, err
	}
	s := &h.slots[a.index]
	if !s.access || s.generation != a.generation || s.failed {
		return nil, nil, resourcev4.ErrOwner
	}
	a.active = true
	return h, s, nil
}
func (a *retainedLiveAccess) finish() {
	a.mu.Lock()
	a.active = false
	if !a.closed {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	a.release()
}
func (a *retainedLiveAccess) release() {
	a.mu.Lock()
	if a.released || a.active {
		a.mu.Unlock()
		return
	}
	a.released = true
	h := a.host
	h.mu.Lock()
	if !h.cleaned {
		s := &h.slots[a.index]
		if s.generation == a.generation {
			s.access = false
		}
	}
	h.mu.Unlock()
	a.host = nil
	a.mu.Unlock()
	h.collect(nil)
	close(a.done)
}
func (a *retainedLiveAccess) Material() (LiveAuthorizationMaterial, error) {
	h, s, err := a.begin()
	if err != nil {
		return LiveAuthorizationMaterial{}, err
	}
	defer a.finish()
	return LiveAuthorizationMaterial{Plan: s.plan, Artifact: s.credential, Trust: h.template.config.Trust[0], Deadline: s.deadline, ServerAllow: s.serverAllow}, nil
}
func (a *retainedLiveAccess) Check(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	h, s, err := a.begin()
	if err != nil {
		return err
	}
	defer a.finish()
	if err = h.checkIssue(ctx, s); err != nil {
		return err
	}
	if s.server != nil {
		return liveArtifactCall(func() error { return s.server.Check(ctx) })
	}
	return nil
}
func (a *retainedLiveAccess) CheckLiveSpend(identity ledgerv4.SQLiteIdentity, fields protocolv4.LiveActivationFields) error {
	h, s, err := a.begin()
	if err != nil {
		return err
	}
	defer a.finish()
	if fields != s.fields {
		return ledgerv4.ErrConflict
	}
	if err = liveArtifactCall(func() error { return h.template.config.Policy.CheckLiveSpend(identity, fields) }); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checkLocked()
}
func (a *retainedLiveAccess) Authorize(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, resourcev4.ErrConfiguration
	}
	h, s, err := a.begin()
	if err != nil {
		return false, err
	}
	defer a.finish()
	if err = h.checkIssue(ctx, s); err != nil {
		return false, err
	}
	h.mu.Lock()
	if err = h.checkLocked(); err == nil && s.policyStarted {
		err = resourcev4.ErrOwner
	}
	if err == nil {
		s.policyStarted = true
	}
	h.mu.Unlock()
	if err != nil {
		return false, err
	}
	var allowed bool
	err = liveArtifactCall(func() error {
		var e error
		allowed, e = h.template.config.Policy.AuthorizeLiveArtifact(ctx, s.fields)
		return e
	})
	if err != nil {
		return false, err
	}
	if err = h.checkIssue(ctx, s); err != nil {
		return false, err
	}
	return allowed, nil
}
func (a *retainedLiveAccess) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	active := a.active
	a.mu.Unlock()
	if !active {
		a.release()
	}
	<-a.done
}

var _ protocolv4.ArtifactIssueRetention = (*LiveArtifactHost)(nil)
var _ LiveAuthorizationHost = (*LiveArtifactHost)(nil)
