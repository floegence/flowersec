package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ServiceContractTarget selects one explicit method. A wanted digest selects
// exact semantics; its absence reads the current advertisement. The local
// Offer bound comes from trusted application policy, never from the response.
// A digest alone cannot assert ownership of a known canonical contract body.
type ServiceContractTarget struct {
	Namespace        string
	Type             uint32
	Wanted           [32]byte
	HasWanted        bool
	MaxOfferWindowMS uint64
	// Known must be the SDK-owned full body returned by a previous query.
	// Close prevents new borrows but does not invalidate already admitted work.
	Known      *ContractQuerySnapshots
	KnownIndex int
}

// QueryServiceContracts uses the Session's existing ordinary RPC channel and
// original fixed SDK query lane. The full owned result is admitted before
// publication, independently of ordinary application completion capacity.
func (s *EnvironmentSession) QueryServiceContracts(ctx context.Context, targets []ServiceContractTarget) (*ContractQuerySnapshots, error) {
	q, err := s.beginServiceContractQuery(ctx, targets)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	if err := q.Wait(ctx); err != nil {
		return nil, err
	}
	return q.Take()
}

func (s *EnvironmentSession) beginServiceContractQuery(ctx context.Context, targets []ServiceContractTarget) (*ContractQueryAcquisition, error) {
	return s.beginServiceContractQueryUntil(ctx, targets, nil, nil, nil)
}

// Batches fork the same original acquisition deadline, including its earliest
// monotonic projection. A later batch cannot renew Bind or Refresh time.
func (s *EnvironmentSession) beginServiceContractQueryUntil(ctx context.Context, targets []ServiceContractTarget, original *timev4.Deadline, claim *contractQueryClaim, bindingKnown []protocolv4.ContractQueryKnown) (*ContractQueryAcquisition, error) {
	if s == nil || ctx == nil || len(targets) < 1 || len(targets) > 8 {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := checkApplicationContext(ctx); err != nil {
		return nil, err
	}
	if bindingKnown != nil && (len(bindingKnown) != len(targets) || claim == nil) {
		return nil, cryptov4.ErrConfiguration
	}
	if claim != nil && claim.protection != nil {
		for _, target := range targets {
			if target.Known != nil {
				return nil, cryptov4.ErrConfiguration
			}
		}
	}
	var wireTargets [8]protocolv4.ContractQueryTarget
	var known [8]protocolv4.ContractQueryKnown
	var windows [8]uint64
	for i, target := range targets {
		wireTargets[i] = protocolv4.ContractQueryTarget{Namespace: target.Namespace, Type: target.Type, Wanted: target.Wanted, HasWanted: target.HasWanted}
		windows[i] = target.MaxOfferWindowMS
	}
	if err := validateContractQueryTargets(wireTargets[:len(targets)], known[:len(targets)]); err != nil {
		return nil, err
	}
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	core.plan.mu.Lock()
	r, closed := core.plan.rpc, core.plan.closed
	clock, timeout, cap := core.plan.config.Clock, core.plan.config.DispatchTimeoutMS, core.plan.config.Session.SessionNotAfterMS
	core.plan.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	if r == nil {
		return nil, cryptov4.ErrNotReady
	}
	e, err := r.bindingEnvironment()
	if err != nil {
		return nil, err
	}
	var knownOwners [8]*ContractQuerySnapshots
	defer func() {
		for _, owner := range knownOwners {
			if owner != nil {
				owner.releaseQueryBorrow()
			}
		}
	}()
	for i, target := range targets {
		if bindingKnown != nil && bindingKnown[i] != nil {
			if target.Known != nil || target.KnownIndex != 0 {
				return nil, cryptov4.ErrConfiguration
			}
			known[i] = bindingKnown[i]
			policy, err := known[i].Policy()
			if err != nil {
				return nil, err
			}
			wireTargets[i].HasKnown, wireTargets[i].Known = true, policy.Digest
			continue
		}
		if target.Known == nil {
			if target.KnownIndex != 0 {
				return nil, cryptov4.ErrConfiguration
			}
			continue
		}
		known[i], err = target.Known.borrowQuery(target.KnownIndex, e)
		if err != nil {
			return nil, err
		}
		knownOwners[i] = target.Known
		policy, err := known[i].Policy()
		if err != nil {
			return nil, err
		}
		wireTargets[i].HasKnown, wireTargets[i].Known = true, policy.Digest
	}
	if err := validateContractQueryTargets(wireTargets[:len(targets)], known[:len(targets)]); err != nil {
		return nil, err
	}
	var deadline *timev4.Deadline
	if original == nil {
		deadline, err = timev4.NewAge(clock, timeout, cap)
	} else if !original.BelongsTo(clock) {
		err = timev4.ErrOwner
	} else {
		deadline, err = original.Fork(min(original.Cap(), cap))
	}
	if err != nil {
		return nil, err
	}
	charge, err := ContractQuerySnapshotsCharge(len(targets))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.draining.Load() {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	publisher := r.rpcPublisherLocked()
	if publisher == nil {
		r.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	if r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	if claim != nil && claim.protection != nil {
		// The protected path transfers its original complete destination;
		// it must never fall back to a fresh root reservation under pressure.
		reservation := claim.destination
		r.mu.Unlock()
		if reservation == (resourcev4.Reference{}) {
			return nil, cryptov4.ErrConfiguration
		}
		return e.beginContractQuery(ctx, s, publisher, wireTargets[:len(targets)], known[:len(targets)], windows[:len(targets)], deadline.Cap(), deadline, claim, reservation)
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "contract-query4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	hash := sha256.Sum256(seed[:])
	owner := r.owner
	copy(owner.Instance[:], hash[:16])
	copy(owner.Backing[:], hash[16:])
	reservation, err := r.root.Reserve(owner, charge, r.accounts[:r.accountCount]...)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer reservation.Release()
	q, err := e.beginContractQuery(ctx, s, publisher, wireTargets[:len(targets)], known[:len(targets)], windows[:len(targets)], deadline.Cap(), deadline, claim, reservation)
	if err != nil {
		return nil, err
	}
	// The worker may already have exited, but the owner cannot be removed while
	// this gate is held. Transfer or release the actual retained bodies once.
	q.mu.Lock()
	if q.environment != nil {
		q.knownOwners = knownOwners
		knownOwners = [8]*ContractQuerySnapshots{}
	}
	q.mu.Unlock()
	return q, nil
}

func (s *ContractQuerySnapshots) borrowQuery(index int, environment *Environment) (protocolv4.ContractQueryKnown, error) {
	if s == nil || environment == nil {
		return nil, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, cryptov4.ErrClosed
	}
	if s.borrows == 32 {
		return nil, cryptov4.ErrCapacity
	}
	if err := s.backing.CheckSameEnvironment(environment.reservation); err != nil {
		return nil, err
	}
	known, err := s.validated.Known(index)
	if err != nil {
		return nil, err
	}
	s.borrows++
	return known, nil
}

func (s *ContractQuerySnapshots) releaseQueryBorrow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.borrows--
	s.releaseLocked()
}

// Validate before cloning names, taking destination backing or registering a
// worker. In particular an oversized namespace cannot allocate outside Q2's
// already bounded metadata, even when the network would later reject it.
func validateContractQueryTargets(targets []protocolv4.ContractQueryTarget, known []protocolv4.ContractQueryKnown) error {
	if len(targets) < 1 || len(targets) > 8 || len(known) != len(targets) {
		return cryptov4.ErrConfiguration
	}
	var scratch [512]byte
	for i, target := range targets {
		if len(target.Namespace) < 1 || len(target.Namespace) > 128 || target.Type == 0 || target.HasWanted && target.HasKnown && target.Wanted != target.Known {
			return cryptov4.ErrConfiguration
		}
		if _, err := protocolv4.EncodeMap(scratch[:], "ContractTarget", []protocolv4.Field{{Name: "service_namespace", Kind: protocolv4.TextString, Text: target.Namespace}, {Name: "method_type_id", Number: uint64(target.Type)}}); err != nil {
			return err
		}
		for _, earlier := range targets[:i] {
			if earlier.Namespace == target.Namespace && earlier.Type == target.Type {
				return cryptov4.ErrConfiguration
			}
		}
		if !target.HasKnown {
			if known[i] != nil {
				return cryptov4.ErrConfiguration
			}
			continue
		}
		if known[i] == nil {
			return cryptov4.ErrConfiguration
		}
		policy, err := known[i].Policy()
		if err != nil {
			return err
		}
		if policy.Namespace != target.Namespace || policy.Type != target.Type || policy.Digest != target.Known {
			return rpcv4.ErrAssociation
		}
	}
	return nil
}
