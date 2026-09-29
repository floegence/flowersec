package sessionv4

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type TopUpOptions struct{ DesiredCount, MaxItemBytes uint32 }
type TopUpState string

const (
	TopUpPending   TopUpState = "pending"
	TopUpInstalled TopUpState = "installed"
	TopUpAcked     TopUpState = "acked"
	TopUpTerminal  TopUpState = "terminal"
)

// TopUpResult separates the original operation's proven frontier from this
// caller's wait/transport error. Empty State means no operation was associated.
// Operation IDs and material/identity bytes never leave the opaque handle.
type TopUpResult struct {
	State         TopUpState
	Options       TopUpOptions
	Handle        *TopUpHandle
	Outcome       string
	TerminalError *protocolv4.V4TopUpError
	CallError     error
}
type TopUpRecoveryResult struct {
	Count      uint8
	Operations [1]TopUpResult
	CallError  error
}

// The observation has no pointer to a source, store, key, material or sender.
// After the original tail exits it is an immutable application-held outcome;
// the source retains at most its current operation, never an operation history.
type topUpObservation struct {
	mu       sync.Mutex
	owner    [16]byte
	state    TopUpState
	options  TopUpOptions
	outcome  string
	terminal protocolv4.V4TopUpError
	done     chan struct{}
	exited   bool
	handle   TopUpHandle
}
type TopUpHandle struct{ observation *topUpObservation }

func (*TopUpHandle) String() string               { return "Flowersec.TopUpHandle" }
func (*TopUpHandle) GoString() string             { return "Flowersec.TopUpHandle" }
func (*TopUpHandle) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (h *TopUpHandle) WaitCleanup(ctx context.Context) error {
	if h == nil || h.observation == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-h.observation.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (o *topUpObservation) result(err error) TopUpResult {
	if o == nil {
		return TopUpResult{CallError: err}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r := TopUpResult{State: o.state, Options: o.options, Outcome: o.outcome, CallError: err}
	if o.state == TopUpPending || o.state == TopUpInstalled {
		r.Handle = &o.handle
	}
	if o.terminal.Code != "" {
		fact := o.terminal
		r.TerminalError = &fact
	}
	return r
}
func (o *topUpObservation) finish() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.exited {
		o.exited = true
		close(o.done)
	}
}

// TopUpIdentityProvider transfers a sole advertisement for a fully validated
// current identity, plus its opaque persistent provider locator. The worker
// captures it once before Begin; later rotation cannot replace that use.
// The original method must join its real provider tails before returning.
type TopUpIdentityProvider interface {
	SnapshotPoolIdentity(context.Context, []byte) (*ApplicationIdentity, int, error)
}

// TopUpFenceProvider talks to the independently authenticated control authority.
// Consumers do not receive the authority's signing key. The worker verifies the
// complete returned proof before transmitting it to the pool authority.
type TopUpFenceProvider interface {
	GetTopUpOwnerProof(context.Context, protocolv4.TopUpRequestFacts, uint64, []byte) (int, error)
}

// TopUpExchangeResult is returned only by an independently authenticated method
// adapter. Error codes alone never prove terminal history. A terminal requires
// its original authenticated receipt, checked again by the SQLite journal.
// Empty Code is success (or replay); only TopUp then has ResponseBytes > 0.
type TopUpExchangeResult struct {
	Code          protocolv4.V4TopUpErrorCode
	Replay        bool
	ResponseBytes int
	Terminal      ledgerv4.TopUpServerSnapshot
	Evidence      ledgerv4.TopUpTerminalEvidence
	Fence         ledgerv4.TopUpPermanentFenceReceipt
	FenceEvidence ledgerv4.TopUpPermanentFenceEvidence
}

// Release returns only this reply's admitted receipt ownership. It cannot
// cancel the source, change durable history or manufacture a terminal result.
func (r *TopUpExchangeResult) Release() {
	if r == nil {
		return
	}
	evidence, fence := r.Evidence, r.FenceEvidence
	r.Evidence, r.FenceEvidence = nil, nil
	// Detach before calling application hooks so reentrant release is inert.
	// Both original responsibilities must leave even if the first hook panics
	// or calls runtime.Goexit; callers retain their position through this tail.
	if e, ok := fence.(interface{ ReleaseTopUpEvidence() }); ok {
		defer e.ReleaseTopUpEvidence()
	}
	if e, ok := evidence.(interface{ ReleaseTopUpEvidence() }); ok {
		e.ReleaseTopUpEvidence()
	}
}

// TopUpControlTransport fixes target, tenant/source permission and transient
// method contracts independently. It joins all request/response provider tails
// before returning, including cancellation. The control adapter owns 41006 and
// 41007; neither method is a core execution-header operation.
type TopUpControlTransport interface {
	TopUp(context.Context, []byte, []byte) (TopUpExchangeResult, error)
	Ack(context.Context, []byte) (TopUpExchangeResult, error)
}

type PoolSourceConfig struct {
	Pool                                                      *MaterialPool
	Access                                                    ledgerv4.TopUpAccess
	Identities                                                TopUpIdentityProvider
	Proofs                                                    TopUpFenceProvider
	Transport                                                 TopUpControlTransport
	FenceKey                                                  protocolv4.TopUpFenceAuthority
	Clock                                                     *timev4.Clock
	RequestLifetimeMS, RecoveryWindowMS, CallMS, RuntimeBytes uint64
	MaxWaiters                                                uint16
}
type topUpOperation struct {
	recovery     ledgerv4.TopUpRecovery
	begun        bool
	keyReference [512]byte
	keyBytes     int
	identity     identityUse
	view         *topUpObservation
}
type topUpRound struct {
	window   *timev4.Window
	deadline *timev4.Deadline
	send     bool
	options  TopUpOptions
	view     *topUpObservation
	err      error
	done     chan struct{}
	cancel   context.CancelFunc
}

// PreauthorizedPoolSource owns one finite control worker and one unresolved
// durable intent. Explicit TopUp calls join that intent; waiting cancellation
// never cancels its worker. Close is the one local cancellation owner.
type PreauthorizedPoolSource struct {
	mu                                  sync.Mutex
	config                              PoolSourceConfig
	pool                                *MaterialPool
	reservation, shared                 resourcev4.Reference
	localID                             [16]byte
	codec                               *protocolv4.TopUpCodec
	wire, response, proof, keyReference []byte
	current                             *topUpOperation
	round                               *topUpRound
	waiters                             uint16
	closed                              bool
	ctx                                 context.Context
	cancel                              context.CancelFunc
	wake                                chan struct{}
	done                                chan struct{}
	cleanup                             <-chan struct{}
}

func (*PreauthorizedPoolSource) String() string               { return "Flowersec.PreauthorizedPoolSource" }
func (*PreauthorizedPoolSource) GoString() string             { return "Flowersec.PreauthorizedPoolSource" }
func (*PreauthorizedPoolSource) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func PoolSourceCharge(c PoolSourceConfig) (resourcev4.Vector, error) {
	if c.Pool == nil || c.Access == nil || c.Identities == nil || c.Proofs == nil || c.Transport == nil || c.Clock == nil || c.FenceKey.KeyID == ([16]byte{}) || c.FenceKey.PublicKey == ([32]byte{}) || c.RequestLifetimeMS == 0 || c.RequestLifetimeMS > 90000 || c.RecoveryWindowMS == 0 || c.RecoveryWindowMS > 86400000 || c.CallMS == 0 || c.CallMS > 90000 || c.RuntimeBytes == 0 || c.MaxWaiters == 0 || c.MaxWaiters > 64 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	codec, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	size := uint64(unsafe.Sizeof(PreauthorizedPoolSource{})) + uint64(unsafe.Sizeof(topUpOperation{})) + uint64(unsafe.Sizeof(topUpObservation{})) + uint64(unsafe.Sizeof(topUpRound{})) + codec + 2*524288 + 1024
	return (resourcev4.Vector{resourcev4.SDKBytes: size, resourcev4.Items: 7, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}
func NewPreauthorizedPoolSource(c PoolSourceConfig, reservation resourcev4.Reference) (*PreauthorizedPoolSource, error) {
	cost, err := PoolSourceCharge(c)
	if err != nil {
		return nil, err
	}
	p := c.Pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.source != nil {
		return nil, cryptov4.ErrTransition
	}
	if c.Clock != p.environment.materialClock {
		return nil, cryptov4.ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(p.reservation); err != nil {
		return nil, err
	}
	shared, err := p.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	s := &PreauthorizedPoolSource{config: c, pool: p, reservation: owned, shared: shared, wire: make([]byte, 524288), response: make([]byte, 524288), proof: make([]byte, 512), keyReference: make([]byte, 512), wake: make(chan struct{}, 1), done: make(chan struct{}), cleanup: p.done}
	s.codec, err = protocolv4.NewTopUpCodec()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	// Local observation identity has no wire or takeover meaning.
	if _, err = rand.Read(s.localID[:]); err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	p.source = s
	go s.run()
	return s, nil
}

func (s *PreauthorizedPoolSource) access() error {
	// Called outside ownership locks; this is a trusted finite local gate.
	if s == nil {
		return cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	access, p := s.config.Access, s.pool
	s.mu.Unlock()
	if access == nil || p == nil {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	if err := access.CheckTopUpAccess(p.tenant, p.generation.Source); err != nil {
		return poolError(protocolv4.V4TopUpErrorCodePermissionDenied)
	}
	return nil
}
func (s *PreauthorizedPoolSource) TopUp(ctx context.Context, options TopUpOptions) TopUpResult {
	return s.submit(ctx, options, true)
}
func (s *PreauthorizedPoolSource) submit(ctx context.Context, options TopUpOptions, send bool) TopUpResult {
	if ctx == nil {
		return TopUpResult{CallError: cryptov4.ErrConfiguration}
	}
	if err := s.access(); err != nil {
		return TopUpResult{CallError: err}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return TopUpResult{CallError: poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)}
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return TopUpResult{CallError: err}
	}
	if s.waiters == s.config.MaxWaiters {
		s.mu.Unlock()
		return TopUpResult{CallError: poolError(protocolv4.V4TopUpErrorCodeCapacityExhausted)}
	}
	r := s.round
	if r == nil {
		r = &topUpRound{send: send, options: options, done: make(chan struct{})}
		if s.current != nil {
			r.view = s.current.view
		}
		s.round = r
		select {
		case s.wake <- struct{}{}:
		default:
		}
	} else if send && !r.send {
		r.send = true
		r.options = options
	}
	s.waiters++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.waiters--; s.mu.Unlock() }()
	var err error
	select {
	case <-r.done:
	case <-ctx.Done():
		err = ctx.Err()
	}
	s.mu.Lock()
	view := r.view
	if err == nil {
		err = r.err
	}
	s.mu.Unlock()
	if accessErr := s.access(); topUpPermissionDenied(accessErr) {
		return TopUpResult{CallError: accessErr}
	}
	return view.result(err)
}
func (s *PreauthorizedPoolSource) TopUpStatus(ctx context.Context, h *TopUpHandle) TopUpResult {
	if s == nil || ctx == nil || h == nil || h.observation == nil {
		return TopUpResult{CallError: cryptov4.ErrConfiguration}
	}
	if h.observation.owner != s.localID {
		return TopUpResult{CallError: poolError(protocolv4.V4TopUpErrorCodePermissionDenied)}
	}
	if err := s.access(); err != nil {
		if topUpPermissionDenied(err) {
			return TopUpResult{CallError: err}
		}
		return h.observation.result(err)
	}
	if err := ctx.Err(); err != nil {
		return h.observation.result(err)
	}
	return h.observation.result(nil)
}
func (s *PreauthorizedPoolSource) RecoverPendingTopUps(ctx context.Context, tenant string, source [16]byte) TopUpRecoveryResult {
	if err := s.access(); err != nil {
		return TopUpRecoveryResult{CallError: err}
	}
	s.mu.Lock()
	p := s.pool
	s.mu.Unlock()
	if p == nil || p.tenant != tenant || p.generation.Source != source {
		return TopUpRecoveryResult{CallError: poolError(protocolv4.V4TopUpErrorCodePermissionDenied)}
	}
	r := s.submit(ctx, TopUpOptions{}, false)
	out := TopUpRecoveryResult{CallError: r.CallError}
	if r.State != "" {
		out.Count = 1
		out.Operations[0] = r
	}
	return out
}
func (s *PreauthorizedPoolSource) Acquire(ctx context.Context, r MaterialRequirements) (*ConnectionMaterial, error) {
	return s.acquirePrepared(ctx, r, nil)
}

func (s *PreauthorizedPoolSource) acquirePrepared(ctx context.Context, r MaterialRequirements, subscriptions *protocolv4.CredentialSubscriptions) (*ConnectionMaterial, error) {
	if err := s.access(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	p, closed := s.pool, s.closed
	s.mu.Unlock()
	if p == nil || closed {
		return nil, poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	m, err := p.acquirePrepared(ctx, r, subscriptions)
	if accessErr := s.access(); topUpPermissionDenied(accessErr) {
		if m != nil {
			m.Close()
		}
		return nil, accessErr
	}
	if err != nil {
		return nil, sourceCallError(err)
	}
	err = s.access()
	if err != nil {
		m.Close()
		return nil, sourceCallError(err)
	}
	return m, nil
}
func (s *PreauthorizedPoolSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	p := s.pool
	s.mu.Unlock()
	if p != nil {
		p.Close()
	} else {
		s.stop()
	}
}
func (s *PreauthorizedPoolSource) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
}
func (s *PreauthorizedPoolSource) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// advance only observes trusted local gates and requests cancellation. It never
// creates another sender or treats a canceled wait as an operation terminal.
func (s *PreauthorizedPoolSource) advance() {
	s.mu.Lock()
	r := s.round
	closed := s.closed
	cancel := context.CancelFunc(nil)
	if r != nil {
		cancel = r.cancel
	}
	s.mu.Unlock()
	if closed {
		return
	}
	if err := s.check(); err != nil && cancel != nil {
		cancel()
	}
}
func (s *PreauthorizedPoolSource) check() error {
	if err := s.access(); err != nil {
		return err
	}
	s.mu.Lock()
	ctx, reservation, shared, p := s.ctx, s.reservation, s.shared, s.pool
	var window *timev4.Window
	var deadline *timev4.Deadline
	if s.round != nil {
		window, deadline = s.round.window, s.round.deadline
	}
	s.mu.Unlock()
	if p == nil {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if window != nil {
		if err := window.Check(); err != nil {
			return err
		}
	}
	if deadline != nil {
		if err := deadline.Check(); err != nil {
			return err
		}
	}
	if err := reservation.Check(); err != nil {
		return err
	}
	if err := shared.Check(); err != nil {
		return err
	}
	p.mu.Lock()
	journal := p.journal
	p.mu.Unlock()
	if journal == nil {
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
	return journal.CheckCurrentOwner()
}

func sourceCallError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var failure ledgerv4.TopUpFailure
	if errors.As(err, &failure) {
		fact, ok := protocolv4.TopUpErrorProjection(failure.Fact.Code, protocolv4.V4TopUpWriteActionNone)
		if ok {
			return ledgerv4.TopUpFailure{Fact: fact}
		}
	}
	var cbor protocolv4.CBORFailure
	if errors.As(err, &cbor) {
		if _, ok := protocolv4.TopUpErrorProjection(protocolv4.V4TopUpErrorCode(cbor), protocolv4.V4TopUpWriteActionNone); ok {
			return poolError(protocolv4.V4TopUpErrorCode(cbor))
		}
	}
	switch {
	case errors.Is(err, ledgerv4.ErrUnknown), errors.Is(err, ledgerv4.ErrStorageFormat):
		return poolError(protocolv4.V4TopUpErrorCodeSourceStateUnknown)
	case errors.Is(err, ledgerv4.ErrConflict):
		return poolError(protocolv4.V4TopUpErrorCodeOperationConflict)
	case errors.Is(err, ledgerv4.ErrFenced):
		return poolError(protocolv4.V4TopUpErrorCodeStaleGeneration)
	case errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, cryptov4.ErrCapacity), errors.Is(err, ledgerv4.ErrCapacity):
		return poolError(protocolv4.V4TopUpErrorCodeCapacityExhausted)
	case errors.Is(err, ErrSourceContractInvalid), errors.Is(err, cryptov4.ErrConfiguration):
		return poolError(protocolv4.V4TopUpErrorCodeSourceContractInvalid)
	case errors.Is(err, timev4.ErrExpired):
		return poolError(protocolv4.V4TopUpErrorCodeTopUpRequestExpired)
	default:
		return poolError(protocolv4.V4TopUpErrorCodeSourceUnavailable)
	}
}

func topUpPermissionDenied(err error) bool {
	var failure ledgerv4.TopUpFailure
	return errors.As(err, &failure) && failure.Fact.Code == protocolv4.V4TopUpErrorCodePermissionDenied
}
