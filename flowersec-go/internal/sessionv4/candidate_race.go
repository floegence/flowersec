package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ErrCandidateExhausted means this immutable provider snapshot has no further
// eligible numeric address. Policy/pin refusal also ends this candidate;
// providers must never retry the same endpoint under weaker TLS policy.
var ErrCandidateExhausted = errors.New("sessionv4: candidate preparation exhausted")
var ErrPreparationBudget = errors.New("sessionv4: preparation budget exhausted")

// candidateRace is embedded in the original admitted source. Two fixed method
// positions include canceled provider/Close tails; a position is reused only
// after its actual original method and cleanup finish. No loser holds final
// Session capacity or obtains credential-bearing I/O.
type candidateRace struct {
	mu                    sync.Mutex
	source                *sourcePreparation
	session               *EnvironmentSession
	config                SessionAdmissionConfig
	slots                 [2]candidatePreparation
	wake                  chan struct{}
	next, ordinal         int
	attempts, bytes, work uint64
	winner                *PreparedCarrier
	winnerSlot            *candidatePreparation
	winnerConfig          SessionAdmissionConfig
	nextStart             time.Time
	closed                bool
	last                  error
}

type candidatePreparation struct {
	ctx                 sessionRuntimeContext
	done                chan struct{}
	route               []byte
	member              protocolv4.PoolMember
	config              SessionAdmissionConfig
	cleanupError        error
	retained            *PreparedCarrier
	retainedReservation resourcev4.Reference
}

func (r *candidateRace) init(p *sourcePreparation, s *EnvironmentSession, c SessionAdmissionConfig) {
	r.source, r.session, r.config = p, s, c
	r.wake = make(chan struct{}, 1)
	for i := range r.slots {
		r.slots[i].route = make([]byte, p.config.Limits.Hello.RouteBytes)
	}
}

func (r *candidateRace) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *candidateRace) stopLocked(winner *candidatePreparation) {
	for i := range r.slots {
		slot := &r.slots[i]
		if slot != winner && slot.done != nil {
			slot.ctx.cancel()
		}
	}
}

func (r *candidateRace) prepare() (*PreparedCarrier, SessionAdmissionConfig, error) {
	p := r.source
	parallel := int(p.config.ParallelCandidates)
	if parallel == 0 {
		parallel = 2
	}
	parallel = min(parallel, int(p.selection.budget.ParallelCandidates))
	timer := time.NewTimer(max(0, time.Until(r.nextStart)))
	defer timer.Stop()
	var tick <-chan time.Time = timer.C
	mayStart := false
	for {
		if err := p.check(r.session); err != nil {
			return nil, r.config, err
		}
		r.mu.Lock()
		if r.winner != nil {
			winner, config := r.winner, r.winnerConfig
			r.mu.Unlock()
			return winner, config, nil
		}
		free, active := -1, 0
		for i := 0; i < parallel; i++ {
			slot := &r.slots[i]
			if slot.done != nil {
				select {
				case <-slot.done:
					if slot.cleanupError != nil {
						r.mu.Unlock()
						return nil, r.config, slot.cleanupError
					}
				default:
					active++
					continue
				}
			}
			if free < 0 {
				free = i
			}
		}
		if r.next == p.selection.count && active == 0 {
			err := r.last
			if err == nil {
				err = ErrCandidateExhausted
			}
			r.mu.Unlock()
			return nil, r.config, err
		}
		start := mayStart && free >= 0 && r.next < p.selection.count
		if start {
			r.next++
		}
		position := r.next - 1
		r.mu.Unlock()
		if start {
			slot := &r.slots[free]
			member, route, err := p.selection.candidate(position, slot.route)
			config := r.config
			if err == nil {
				err = p.material.lease.lease.maps[0].CheckDirectConnectionRequirements(member.Index, config.Requirements)
			}
			if err == nil {
				config.Features, err = p.material.lease.lease.maps[0].FeatureEnvelope(member.Index, protocolv4.FeatureEnvelopePolicy{LocalCapabilities: p.config.LocalCapabilities, ProposedOffer: p.config.Hello.Offered, RouteAllowedFeatures: p.config.Hello.Policy.RouteAllowedFeatures})
			}
			if err == nil {
				_, _, err = SessionAdmissionRequirements(config)
			}
			if err != nil {
				r.mu.Lock()
				r.last = err
				r.mu.Unlock()
				continue
			}
			r.mu.Lock()
			slot.ctx = sessionRuntimeContext{parent: &r.session.context, done: make(chan struct{})}
			slot.done, slot.member, slot.config, slot.cleanupError = make(chan struct{}), member, config, nil
			r.mu.Unlock()
			go r.run(slot, route)
			mayStart = false
			r.nextStart = time.Now().Add(250 * time.Millisecond)
			timer.Reset(250 * time.Millisecond)
			tick = timer.C
			continue
		}
		select {
		case <-r.session.context.Done():
			return nil, r.config, r.session.context.Err()
		case <-r.wake:
		case <-tick:
			mayStart = true
			tick = nil
		}
	}
}

// claimAttempt consumes the complete qualified allowance before any provider
// call. Failure/cancellation does not refund cumulative signed attempt budget.
func (r *candidateRace) claimAttempt(address uint8) (resourcev4.Reference, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.source
	if r.closed || r.winner != nil {
		return resourcev4.Reference{}, cryptov4.ErrClosed
	}
	b, cost := p.selection.budget, p.config.AttemptBudget
	count := uint64(address) + 1
	if count > b.CandidateAddressAttempts || cost.PreauthBytes > b.CandidatePreauthBytes/count || cost.WorkUnits > b.CandidateWorkUnits/count ||
		r.attempts >= b.TotalAddressAttempts || cost.PreauthBytes > b.TotalPreauthBytes-r.bytes || cost.WorkUnits > b.TotalWorkUnits-r.work {
		return resourcev4.Reference{}, ErrPreparationBudget
	}
	if err := p.check(r.session); err != nil {
		return resourcev4.Reference{}, err
	}
	charge, err := PreparedCarrierCharge(p.config.CarrierRuntimeBytes)
	if err != nil {
		return resourcev4.Reference{}, err
	}
	var ref resourcev4.Reference
	if r.ordinal == 0 {
		ref = p.config.CarrierReservation
		err = ref.Check()
	} else {
		ref, err = p.config.Root.Reserve(admissionResourceKey(p.config.Owner, 400+uint32(r.ordinal)), charge, p.config.Scope.Tenant)
	}
	if err != nil {
		return resourcev4.Reference{}, err
	}
	r.ordinal++
	r.attempts++
	r.bytes += cost.PreauthBytes
	r.work += cost.WorkUnits
	return ref, nil
}

func retirePrepared(p *PreparedCarrier) error {
	if p == nil {
		return nil
	}
	_ = p.Close()
	if err := p.WaitCleanup(context.Background()); err != nil {
		return err
	}
	return p.Retire()
}

func (r *candidateRace) run(slot *candidatePreparation, route []byte) {
	var prepared *PreparedCarrier
	var ref resourcev4.Reference
	err := ErrEnvironmentTaskExit
	returned, handed := false, false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		if slot.cleanupError != nil {
			slot.retained, slot.retainedReservation = prepared, ref
		}
		r.mu.Lock()
		if err != nil {
			r.last = err
		}
		r.signal()
		close(slot.done)
		r.mu.Unlock()
	}()
	defer func() {
		if !handed && slot.cleanupError == nil {
			// An abnormal Close/WaitCleanup/Retire leaves the original charge
			// retained. The outer defer still joins the real method exit.
			slot.cleanupError = ErrEnvironmentTaskExit
			slot.cleanupError = retirePrepared(prepared)
			if slot.cleanupError == nil {
				ref.Release()
			}
		}
	}()
	p := r.source
	attempts := p.config.AddressAttempts
	if attempts == 0 {
		attempts = 2
	}
	attempts = min(attempts, uint8(p.selection.budget.CandidateAddressAttempts))
	for address := uint8(0); address < attempts; address++ {
		if err = slot.ctx.Err(); err != nil {
			returned = true
			return
		}
		ref, err = r.claimAttempt(address)
		if err != nil {
			returned = true
			return
		}
		request := CarrierPreparationRequest{Config: PreparedCarrierConfig{Candidate: slot.member, Attempt: p.selection.attempt, Session: r.config.Core.Session, Role: protocolv4.ClientToServer, Deadline: p.config.Admission.Initial.Deadline, Reservation: ref, Environment: p.config.Environment, RuntimeBytes: p.config.CarrierRuntimeBytes}, Route: route, AddressAttempt: address, Budget: p.config.AttemptBudget}
		prepared, err = p.config.Carrier.PrepareCarrier(&slot.ctx, request)
		if err == nil && prepared == nil {
			err = cryptov4.ErrConfiguration
		}
		if err == nil {
			err = prepared.Check()
		}
		if err == nil {
			err = slot.config.Requirements.Check(prepared.guarantees)
		}
		if err == nil {
			err = p.material.lease.lease.maps[0].CheckDirectConnectionGuarantees(slot.member.Index, protocolv4.ClientToServer, prepared.guarantees)
		}
		if err == nil {
			binding := prepared.AdmissionBinding()
			if binding.Candidate != slot.member || binding.Attempt != p.selection.attempt || binding.Session != r.config.Core.Session || binding.Role != protocolv4.ClientToServer || binding.MessageCarrier != slot.config.Core.MessageCarrier {
				err = cryptov4.ErrConfiguration
			}
		}
		if err == nil {
			r.mu.Lock()
			if r.closed || r.winner != nil {
				err = cryptov4.ErrClosed
			} else {
				err = slot.ctx.Err()
			}
			if err == nil {
				r.winner, r.winnerSlot, r.winnerConfig = prepared, slot, slot.config
				handed = true
				r.stopLocked(slot)
			}
			r.mu.Unlock()
			if handed {
				returned = true
				return
			}
		}
		slot.cleanupError = ErrEnvironmentTaskExit
		slot.cleanupError = retirePrepared(prepared)
		if slot.cleanupError != nil {
			returned = true
			return
		}
		prepared = nil
		ref.Release()
		ref = resourcev4.Reference{}
		if errors.Is(err, ErrCandidateExhausted) {
			returned = true
			return
		}
	}
	returned = true
}

// rejectWinner is available only while no establishment/admission owns the
// handle. The same original method position retires it while unstarted signed
// candidates may continue. Its canceled competitors never become winners.
func (r *candidateRace) rejectWinner(p *PreparedCarrier) error {
	r.mu.Lock()
	if r.closed || r.winner != p || r.winnerSlot == nil {
		r.mu.Unlock()
		return cryptov4.ErrTransition
	}
	slot := r.winnerSlot
	r.mu.Unlock()
	<-slot.done
	r.mu.Lock()
	p.mu.Lock()
	if p.admission != nil || p.activated {
		p.mu.Unlock()
		r.mu.Unlock()
		return cryptov4.ErrTransition
	}
	p.sealLocked(nil)
	p.mu.Unlock()
	slot.ctx.cancel()
	r.winner, r.winnerSlot = nil, nil
	slot.done = make(chan struct{})
	r.mu.Unlock()
	go func() {
		complete := false
		defer func() {
			if recover() != nil || !complete {
				slot.cleanupError = ErrEnvironmentTaskExit
			}
			if slot.cleanupError != nil {
				slot.retained = p
			}
			r.mu.Lock()
			r.signal()
			close(slot.done)
			r.mu.Unlock()
		}()
		slot.cleanupError = retirePrepared(p)
		complete = true
	}()
	return nil
}

// Cleanup is called by the original Environment worker. Successful publication
// does not discard canceled loser tails: they remain in these positions until
// their actual provider and Close/WaitCleanup/Retire calls have returned.
func (r *candidateRace) cleanup() error {
	if r.source == nil {
		return nil
	}
	r.mu.Lock()
	r.closed = true
	r.stopLocked(nil)
	r.mu.Unlock()
	for i := range r.slots {
		slot := &r.slots[i]
		if slot.done != nil {
			<-slot.done
			if slot.cleanupError != nil {
				return slot.cleanupError
			}
		}
		clear(slot.route)
	}
	// The last completion closes its channel while holding this mutex. Join
	// that final unlock before the enclosing source can clear its backing.
	r.mu.Lock()
	r.mu.Unlock()
	if r.winner != nil && r.winner != r.source.prepared {
		if err := retirePrepared(r.winner); err != nil {
			return err
		}
	}
	return nil
}
