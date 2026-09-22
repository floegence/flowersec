package sessionv4

import (
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func (i *unaryInvocation) checkRequestTime(begun bool) error {
	now, err := i.deadline.Sample()
	if err != nil {
		return err
	}
	return i.checkRequestTimeAt(now, begun)
}

func (i *unaryInvocation) checkRequestTimeAt(now timev4.Sample, begun bool) error {
	if err := i.deadline.CheckAt(now); err != nil {
		return err
	}
	if begun {
		return nil
	}
	p, h := i.policy, i.request.Fields()
	horizon := p.MessageLifetimeMS
	if i.request.HasExecutionIdentity() {
		horizon = p.ExecutionHorizonMS
		cutoff := binary.BigEndian.Uint64(h.OperationID[:8])
		if p.AdmissionWindowMS == 0 || p.AdmissionWindowMS > math.MaxUint64-now.LowerMS || cutoff <= now.UpperMS || cutoff > now.LowerMS+p.AdmissionWindowMS {
			return rpcv4.ErrAdmissionWindowClosed
		}
	}
	if horizon == 0 || horizon > math.MaxUint64-now.LowerMS || h.DeadlineAtMS > now.LowerMS+horizon {
		return timev4.ErrExpired
	}
	return nil
}

// WithRequestPublication has the same authority/lease/owner ordering as the
// decoder trampoline. The original invocation keeps its metadata and exact
// contract while a publisher turn is outside the network lock. No close or
// completed-result cleanup can return these live responsibilities early.
func (i *unaryInvocation) WithRequestPublication(h protocolv4.ApplicationHeader, action func() error) (err error) {
	i.mu.Lock()
	if i.cleaned || i.preparing || i.canceled || i.request != h || action == nil {
		i.mu.Unlock()
		return cryptov4.ErrClosed
	}
	i.publicationUsers++
	plan, services, deadline := i.plan, i.services, i.deadline
	i.mu.Unlock()
	transferred := false
	defer func() {
		i.mu.Lock()
		i.publicationUsers--
		if err != nil && !transferred && i.publicationFailure == nil {
			i.publicationFailure = err
		}
		i.mu.Unlock()
	}()
	// Sampling is outside the finite transfer gates. The action below checks
	// this original snapshot and deadline without calling a host clock source.
	now, err := deadline.Sample()
	if err != nil {
		return err
	}
	l, a, err := plan.queryAuthorization()
	if err != nil {
		return err
	}
	return a.WithCurrentAuthorization(func() error {
		services.mu.Lock()
		defer services.mu.Unlock()
		if services.closed {
			return cryptov4.ErrClosed
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.revoked || l.authorization != a {
			return ErrApplicationAuthorization
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.canceled || i.cleaned {
			return cryptov4.ErrClosed
		}
		if err := i.ctx.Err(); err != nil {
			return err
		}
		if err := i.checkRequestTimeAt(now, i.publication.Progress().HeaderAccepted); err != nil {
			return err
		}
		if i.fixedResultRead {
			if services.resultReadBinding.Type != h.Fields().Type || services.resultReadBinding.Contract != h.Fields().ServiceContractDigest {
				return rpcv4.ErrAssociation
			}
			if err := i.metadata.Check(); err != nil {
				return err
			}
			transferred = true
			return action()
		}
		return i.route.WithRegistered(func() error {
			transferred = true
			return action()
		})
	})
}
