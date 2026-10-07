package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ErrCandidateExhausted means this immutable provider snapshot has no further
// eligible numeric address. Policy/pin refusal also ends this candidate;
// providers must never retry the same endpoint under weaker TLS policy.
var ErrCandidateExhausted = errors.New("sessionv4: candidate preparation exhausted")
var ErrPreparationBudget = errors.New("sessionv4: preparation budget exhausted")

const candidatePreparationMS = 30000
const candidateCleanupMS = 5000

// candidateRace is embedded in the original admitted source. Two fixed method
// positions include canceled provider/Close tails; a position is reused only
// after its actual original method and cleanup finish. No loser holds final
// Session capacity or obtains credential-bearing I/O.
type candidateRace struct {
	mu                                                                sync.Mutex
	source                                                            *sourcePreparation
	session                                                           *EnvironmentSession
	config                                                            SessionAdmissionConfig
	slots                                                             [2]candidatePreparation
	wake                                                              chan struct{}
	next                                                              int
	attempts, bytes, work                                             uint64
	winner                                                            *PreparedCarrier
	winnerSlot                                                        *candidatePreparation
	winnerConfig                                                      SessionAdmissionConfig
	nextStart                                                         time.Time
	preparationWindow                                                 *timev4.Window
	closed                                                            bool
	last                                                              error
	transportFailure                                                  bool
	nonTransportFailure                                               bool
	initialGate                                                       chan struct{}
	initialLimit, initialDispatched, initialStarted, initialUnstarted int
	initialClosed                                                     bool
}

type candidatePreparation struct {
	parent                  preparedCarrierReference
	floor                   *resourcev4.ProtectedReservation
	providerPreparation     CarrierPreparation
	cleanupWindow           *timev4.Window
	ctx                     sessionRuntimeContext
	done                    chan struct{}
	route                   []byte
	member                  protocolv4.PoolMember
	config                  SessionAdmissionConfig
	rpc                     RPCServicesConfig
	cleanupError            error
	retained                *PreparedCarrier
	retainedReservation     resourcev4.Reference
	initial, initialEntered bool
}

func (r *candidateRace) init(p *sourcePreparation, s *EnvironmentSession, c SessionAdmissionConfig) error {
	window, err := timev4.NewWindow(c.Core.Clock, candidatePreparationMS)
	if err != nil {
		return err
	}
	r.source, r.session, r.config = p, s, c
	r.preparationWindow = window
	r.wake = make(chan struct{}, 1)
	if p.config.CandidateStartIntervalConfigured && p.config.CandidateStartIntervalMS == 0 {
		r.initialGate = make(chan struct{})
		parallel := int(p.config.ParallelCandidates)
		if parallel == 0 {
			parallel = 2
		}
		r.initialLimit = min(parallel, p.references.carrierCount, int(p.selection.budget.ParallelCandidates), p.selection.count)
	}
	for i := range r.slots {
		r.slots[i].route = make([]byte, p.config.Limits.Hello.RouteBytes)
		r.slots[i].parent.origin = p.config.Environment
		r.slots[i].parent.idle = p.references.carriers[i]
		p.references.carriers[i] = resourcev4.Reference{}
		r.slots[i].floor, p.references.carrierFloors[i] = p.references.carrierFloors[i], nil
		r.slots[i].providerPreparation, p.references.providerPreparations[i] = p.references.providerPreparations[i], nil
	}
	return nil
}

func (r *candidateRace) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *candidateRace) stopLocked(winner *candidatePreparation, window *timev4.Window) {
	for i := range r.slots {
		slot := &r.slots[i]
		if slot != winner && slot.done != nil {
			if slot.cleanupWindow == nil {
				slot.cleanupWindow = window
			}
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
	parallel = min(parallel, p.references.carrierCount)
	parallel = min(parallel, int(p.selection.budget.ParallelCandidates))
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		if err := p.check(r.session); err != nil {
			return nil, r.config, err
		}
		remaining, err := r.preparationWindow.RemainingMS()
		if err != nil {
			return nil, r.config, err
		}
		if _, _, err := r.loserCleanupRemaining(); err != nil {
			return nil, r.config, err
		}
		mayStart := !time.Now().Before(r.nextStart)
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
			transport := r.transportFailure && !r.nonTransportFailure
			r.mu.Unlock()
			if transport {
				// Only fully exhausted native preparation can supply this fact.
				// Earlier refusal and cleanup failure cannot be hidden by a
				// later disconnected candidate.
				r.session.closeWithSource(err, true)
			}
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
			if err == nil && config.Core.MixedCarrier {
				candidate := p.material.lease.lease.maps[0].Field("candidates").Index(int(member.Index))
				path, ok := candidate.Named("Candidate", "path_kind").Uint()
				leg := "direct_leg"
				if path == 1 {
					leg = "client_leg"
				}
				if !ok || path > 1 {
					err = cryptov4.ErrConfiguration
				} else {
					kind, ok := candidate.Named("Candidate", leg).Named("Leg", "carrier").Uint()
					if !ok || kind > 2 {
						err = cryptov4.ErrConfiguration
					} else {
						config.Core = coreCarrierMode(config.Core, kind == 1)
					}
				}
				if err == nil && config.RPC != nil {
					slot.rpc = *config.RPC
					slot.rpc.Native = config.Core.Native
					config.RPC = &slot.rpc
				}
			}
			if err == nil {
				err = p.material.lease.lease.maps[0].CheckConnectionRequirements(member.Index, config.Requirements)
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
				r.nonTransportFailure = true
				r.closeInitialGateLocked()
				r.mu.Unlock()
				continue
			}
			r.mu.Lock()
			slot.ctx = sessionRuntimeContext{parent: &r.session.context, done: make(chan struct{})}
			slot.done, slot.member, slot.config, slot.cleanupError = make(chan struct{}), member, config, nil
			slot.cleanupWindow = nil
			slot.initial, slot.initialEntered = r.initialGate != nil && position < r.initialLimit, false
			if slot.initial {
				r.initialDispatched++
			}
			r.closeInitialGateLocked()
			r.mu.Unlock()
			go r.run(slot, route)
			spacing := uint64(250)
			if p.config.CandidateStartIntervalConfigured {
				spacing = p.config.CandidateStartIntervalMS
			}
			r.nextStart = time.Now().Add(time.Duration(spacing) * time.Millisecond)
			continue
		}
		// One original timer observes pacing, total preparation and canceled
		// provider tails even when every candidate position is occupied.
		delay := time.Duration(min(remaining, 100)) * time.Millisecond
		if !mayStart {
			delay = min(delay, max(time.Millisecond, time.Until(r.nextStart)))
		}
		timer.Reset(delay)
		select {
		case <-r.session.context.Done():
			return nil, r.config, r.session.context.Err()
		case <-r.wake:
		case <-timer.C:
		}
	}
}

// claimAttempt consumes the complete qualified allowance before any provider
// call. Failure/cancellation does not refund cumulative signed attempt budget.
func (r *candidateRace) claimAttempt(slot *candidatePreparation, address uint8) (resourcev4.Reference, error) {
	if err := r.preparationWindow.Check(); err != nil {
		return resourcev4.Reference{}, err
	}
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
	// The position stays charged through failed preparation and real cleanup.
	// Reuse changes only its original handle generation; no root competition
	// or new owner is introduced by a later address or signed candidate.
	ref, err := slot.floor.Checkout()
	if err != nil {
		return resourcev4.Reference{}, err
	}
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
	var previousFailure error
	transport := false
	returned, handed := false, false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
			transport = false
		}
		if slot.cleanupError != nil {
			slot.retained, slot.retainedReservation = prepared, ref
		}
		r.mu.Lock()
		if slot.initial && !slot.initialEntered {
			r.initialUnstarted++
			r.closeInitialGateLocked()
		}
		if err != nil {
			r.last = err
			r.transportFailure = transport
			r.nonTransportFailure = r.nonTransportFailure || !transport
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
		transport = false
		if err = slot.ctx.Err(); err != nil {
			returned = true
			return
		}
		ref, err = r.claimAttempt(slot, address)
		if err != nil {
			returned = true
			return
		}
		request := CarrierPreparationRequest{Config: PreparedCarrierConfig{Candidate: slot.member, Attempt: p.selection.attempt, Session: r.config.Core.Session, Role: protocolv4.ClientToServer, Deadline: p.config.Admission.Initial.Deadline, Reservation: ref, Environment: p.config.Environment, RuntimeBytes: p.config.CarrierRuntimeBytes}, Route: route, AddressAttempt: address, Budget: p.config.AttemptBudget}
		if p.references.carrierCount != 0 {
			request.Config.originalParent = &slot.parent
			request.Config.originalAlias = slot.parent.snapshot()
		}
		request.Scope = p.config.Scope
		factory := p.config.Carrier
		if slot.providerPreparation != nil {
			factory = slot.providerPreparation
		}
		r.mu.Lock()
		if slot.initial && !slot.initialEntered {
			slot.initialEntered = true
			r.initialStarted++
			r.closeInitialGateLocked()
		}
		r.mu.Unlock()
		prepared, err = factory.PrepareCarrier(&slot.ctx, request)
		if err == nil && r.initialGate != nil {
			select {
			case <-r.initialGate:
			case <-slot.ctx.Done():
				err = slot.ctx.Err()
			}
		}
		addressesExhausted := err == native.ErrAddressesExhausted
		if addressesExhausted {
			if prepared != nil {
				err = cryptov4.ErrConfiguration
			} else if previousFailure != nil {
				err = previousFailure
			}
		}
		// A factory includes policy and binding work. Only a carrier's own
		// native-boundary projection is evidence of preparation interruption.
		transport = err == native.ErrConnectionLost
		if err == nil && prepared == nil {
			err = cryptov4.ErrConfiguration
		}
		if err == nil {
			err = prepared.checkPreparation(request.Config)
		}
		if err == nil {
			err = slot.config.Requirements.Check(prepared.guarantees)
		}
		if err == nil {
			err = p.material.lease.lease.maps[0].CheckConnectionGuarantees(slot.member.Index, protocolv4.ClientToServer, prepared.guarantees)
		}
		if err == nil {
			err = p.material.lease.lease.maps[0].CheckBindingMode(slot.member.Index, p.config.Hello.Policy.BindingMode)
		}
		if err == nil {
			binding := prepared.AdmissionBinding()
			if binding.Candidate != slot.member || binding.Attempt != p.selection.attempt || binding.Session != r.config.Core.Session || binding.Role != protocolv4.ClientToServer || binding.MessageCarrier != slot.config.Core.MessageCarrier {
				err = cryptov4.ErrConfiguration
			}
		}
		if err == nil {
			var policy protocolv4.HelloPolicy
			policy, err = prepared.bindHelloPolicy(p.config.Hello.Policy, r.config.Core.Session.ArtifactDigest)
			clear(policy.Exporter)
		}
		if err == nil {
			var cleanupWindow *timev4.Window
			var now timev4.Mark
			now, err = p.config.Admission.Core.Clock.Monotonic()
			if err == nil {
				err = r.preparationWindow.CheckAt(now)
			}
			if err == nil {
				cleanupWindow, err = timev4.NewWindowAt(p.config.Admission.Core.Clock, now, candidateCleanupMS)
			}
			if err != nil {
				returned = true
				return
			}
			r.mu.Lock()
			if r.closed || r.winner != nil {
				err = cryptov4.ErrClosed
			} else {
				err = slot.ctx.Err()
			}
			if err == nil {
				r.winner, r.winnerSlot, r.winnerConfig = prepared, slot, slot.config
				handed = true
				r.stopLocked(slot, cleanupWindow)
			}
			r.mu.Unlock()
			if handed {
				returned = true
				return
			}
		}
		if err != nil && !transport {
			r.mu.Lock()
			r.nonTransportFailure = true
			r.mu.Unlock()
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
		if addressesExhausted || errors.Is(err, ErrCandidateExhausted) {
			returned = true
			return
		}
		previousFailure = err
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
	window, err := timev4.NewWindow(r.config.Core.Clock, candidateCleanupMS)
	if err != nil {
		return err
	}
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
	if slot.cleanupWindow == nil {
		slot.cleanupWindow = window
	}
	r.nonTransportFailure = true
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
	r.stopLocked(nil, nil)
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

func (r *candidateRace) closeInitialGateLocked() {
	if r.initialGate != nil && !r.initialClosed && r.next >= r.initialLimit && r.initialStarted+r.initialUnstarted >= r.initialDispatched {
		r.initialClosed = true
		close(r.initialGate)
	}
}
