package sessionv4

import (
	"context"
	"crypto/rand"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PreparedCarrierBinding is detached selection data, never activation authority.
// The actual prepared owner and the original admission reservation are required
// for the once-only transfer of its private I/O.
type PreparedCarrierBinding struct {
	Candidate      protocolv4.PoolMember
	Attempt        [16]byte
	Session        protocolv4.ArtifactSessionParameters
	Role           protocolv4.Direction
	MessageCarrier bool
	Native         bool
}

// PreparedCarrierConfig is fixed by trusted local preparation. Endpoint/TLS
// eligibility and bounded DNS/address attempts belong to that original caller.
// No activation credentials or post-spend authorization are required here.
type PreparedCarrierConfig struct {
	relay                    bool
	originalParent           *preparedCarrierReference
	originalAlias            resourcev4.Reference
	originalReservation      resourcev4.Reference
	Candidate                protocolv4.PoolMember
	Attempt                  [16]byte
	Session                  protocolv4.ArtifactSessionParameters
	Role                     protocolv4.Direction
	Deadline                 *timev4.Deadline
	Reservation, Environment resourcev4.Reference
	RuntimeBytes             uint64
}

// TakeReservation moves admitted metadata before physical I/O and preserves
// the original method identity through its constructor transfer.
func (c PreparedCarrierConfig) TakeReservation() (PreparedCarrierConfig, error) {
	if c.originalReservation != (resourcev4.Reference{}) {
		return c, resourcev4.ErrOwner
	}
	charge, err := PreparedCarrierCharge(c.RuntimeBytes)
	if err != nil {
		return c, err
	}
	owned, err := c.Reservation.Take(charge)
	if err != nil {
		return c, err
	}
	c.originalReservation, c.Reservation = c.Reservation, owned
	return c, nil
}

// Both provider forms must expose their actual original cleanup and retirement.
// Close returning alone is not proof that provider tasks or buffers have exited.
type preparedProviderLifecycle interface {
	// CheckEnvironment binds the actual provider charge, not only this wrapper.
	// It is a bounded local check without I/O or application callbacks.
	CheckEnvironment(resourcev4.Reference) error
	// ConnectionGuarantees returns detached observations of this exact
	// provider after preparation. It is bounded trusted SDK work, with no
	// I/O, callback, allocation or claims about an unobserved remote leg.
	ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error)
	Close() error
	WaitCleanup(context.Context) error
	Retire() error
}

// Only an SDK native provider can supply this concrete same-root connection.
// The maintenance stream and data stream graph retain the same connection.
func originalNativeConnection(connection native.Connection) bool {
	switch p := connection.(type) {
	case *rawquic.OwnedConnection:
		return p != nil
	case *webtransport.OwnedConnection:
		return p != nil
	default:
		return false
	}
}

func preparedNativeConnection(provider preparedProviderLifecycle, stream io.ReadWriteCloser, environment resourcev4.Reference) (native.Connection, error) {
	var connection native.Connection
	switch p := provider.(type) {
	case interface {
		NativeConnection() *rawquic.OwnedConnection
	}:
		connection = p.NativeConnection()
	case interface {
		NativeConnection() *webtransport.OwnedConnection
	}:
		connection = p.NativeConnection()
	default:
		return nil, nil
	}
	if stream == nil || !originalNativeConnection(connection) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := connection.CheckEnvironment(environment); err != nil {
		return nil, err
	}
	return connection, nil
}

// PreparedCarrier is a copyable opaque handle. It exposes no unactivated I/O
// and starts no goroutine, timer, callback or cancellation observer. The existing
// Connect owner drives Check/Close and bounded cleanup until activation; the
// existing initial/core owner then drives the same original provider lifecycle.
type PreparedCarrier struct{ *preparedCarrier }

type preparedCarrier struct {
	relay                            bool
	relayBudget                      *relayByteBudget
	originalParent                   *preparedCarrierReference
	originalReservation              resourcev4.Reference
	mu                               sync.Mutex
	incarnation                      [16]byte
	hopChallenge                     [32]byte
	allowRecipient                   *TunnelServerAllowRecipient
	allowRegistered, allowGranted    bool
	binding                          PreparedCarrierBinding
	guarantees                       protocolv4.V4ConnectionGuarantees
	exporterArtifact, exporterValue  [32]byte
	exporterReady                    bool
	parent                           context.Context
	deadline                         *timev4.Deadline
	reservation, environment, shared resourcev4.Reference
	admission                        *SessionAdmissionReservation
	provider                         preparedProviderLifecycle
	native                           native.Connection
	stream                           io.ReadWriteCloser
	messages                         InitialMessages
	streamAdapter                    preparedStream
	messageAdapter                   preparedMessages
	activated, closed                bool
	reading, writing                 bool
	closeStarted, closing, cleaning  bool
	complete, retiring, retired      bool
	cause, closeErr                  error
}

type preparedStream struct{ owner *preparedCarrier }
type preparedMessages struct{ owner *preparedCarrier }

func PreparedCarrierCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	bytes := uint64(unsafe.Sizeof(PreparedCarrier{})) + uint64(unsafe.Sizeof(preparedCarrier{}))
	if runtimeBytes == 0 || runtimeBytes > math.MaxUint64-bytes {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes + runtimeBytes, resourcev4.Items: 1, resourcev4.WorkSlots: 4}, nil
}

// Constructor failure leaves the provider with its caller. Success transfers
// its sole Close/WaitCleanup/Retire responsibility to this canonical owner.
func NewPreparedStream(ctx context.Context, config PreparedCarrierConfig, stream io.ReadWriteCloser) (*PreparedCarrier, error) {
	provider, ok := stream.(preparedProviderLifecycle)
	if stream == nil || !ok {
		return nil, cryptov4.ErrConfiguration
	}
	return newPreparedCarrier(ctx, config, provider, stream, nil)
}

func NewPreparedMessages(ctx context.Context, config PreparedCarrierConfig, messages InitialMessages) (*PreparedCarrier, error) {
	provider, ok := messages.(preparedProviderLifecycle)
	if messages == nil || !ok {
		return nil, cryptov4.ErrConfiguration
	}
	return newPreparedCarrier(ctx, config, provider, nil, messages)
}

func newPreparedCarrier(ctx context.Context, c PreparedCarrierConfig, provider preparedProviderLifecycle, stream io.ReadWriteCloser, messages InitialMessages) (*PreparedCarrier, error) {
	if ctx == nil || c.Deadline == nil || c.Role > protocolv4.ServerToClient || c.Candidate.Index >= 16 || c.Candidate.CandidateID == ([16]byte{}) || c.Candidate.RouteDigest == ([32]byte{}) || c.Attempt == ([16]byte{}) || !c.Session.Contract.Valid() || c.Session.ArtifactDigest == ([32]byte{}) || c.Reservation == c.Environment {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := protocolv4.Profile(c.Session.Profile); err != nil {
		return nil, err
	}
	charge, err := PreparedCarrierCharge(c.RuntimeBytes)
	if err != nil {
		return nil, err
	}
	var incarnation [16]byte
	if _, err = rand.Read(incarnation[:]); err != nil {
		return nil, err
	}
	if incarnation == ([16]byte{}) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.Deadline.Check(); err != nil {
		return nil, err
	}
	if err := c.Reservation.CheckSameEnvironment(c.Environment); err != nil {
		return nil, err
	}
	if err := provider.CheckEnvironment(c.Environment); err != nil {
		return nil, err
	}
	native, err := preparedNativeConnection(provider, stream, c.Environment)
	if err != nil {
		return nil, err
	}
	guarantees, err := provider.ConnectionGuarantees()
	if err != nil {
		return nil, err
	}
	if !guarantees.Valid() {
		return nil, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	if c.Role == protocolv4.ServerToClient {
		guarantees.LocalConsumerTls13Verification = protocolv4.V4ConsumerTLS13VerificationNotApplicable
	}
	var shared resourcev4.Reference
	if c.originalParent == nil {
		shared, err = c.Environment.Borrow()
	} else {
		shared, err = c.originalParent.take(c.Environment, c.originalAlias)
	}
	if err != nil {
		return nil, err
	}
	owned, err := c.Reservation.Take(charge)
	if err != nil {
		c.originalParent.giveBack(shared)
		return nil, err
	}
	var challenge [32]byte
	if _, err = rand.Read(challenge[:]); err != nil || challenge == ([32]byte{}) {
		owned.Release()
		c.originalParent.giveBack(shared)
		return nil, cryptov4.ErrConfiguration
	}
	originalReservation := c.originalReservation
	if originalReservation == (resourcev4.Reference{}) {
		originalReservation = c.Reservation
	}
	p := &preparedCarrier{relay: c.relay, incarnation: incarnation, hopChallenge: challenge, binding: PreparedCarrierBinding{Candidate: c.Candidate, Attempt: c.Attempt, Session: c.Session, Role: c.Role, MessageCarrier: messages != nil, Native: native != nil}, guarantees: guarantees,
		parent: ctx, deadline: c.Deadline, reservation: owned, environment: c.Environment, shared: shared, originalParent: c.originalParent, originalReservation: originalReservation,
		provider: provider, native: native, stream: stream, messages: messages}
	p.streamAdapter.owner, p.messageAdapter.owner = p, p
	return &PreparedCarrier{p}, nil
}

// A factory must return the original method's newly constructed carrier. Equal
// signed tuples do not authorize substituting an independently owned handle or
// reviving a result from an earlier use of the same candidate position.
func (p *PreparedCarrier) checkPreparation(c PreparedCarrierConfig) error {
	if p == nil || p.preparedCarrier == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.relay != c.relay || p.originalReservation != c.Reservation || p.originalParent != c.originalParent ||
		p.environment != c.Environment || p.deadline != c.Deadline || p.admission != nil || p.activated {
		return resourcev4.ErrOwner
	}
	return p.checkLocked()
}

func (p *PreparedCarrier) AdmissionBinding() PreparedCarrierBinding {
	if p == nil || p.preparedCarrier == nil {
		return PreparedCarrierBinding{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.binding
}

func (p *PreparedCarrier) CheckEnvironment(environment resourcev4.Reference) error {
	if p == nil || p.preparedCarrier == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if environment != p.environment {
		return resourcev4.ErrOwner
	}
	return p.reservation.CheckSameEnvironment(environment)
}

func (p *preparedCarrier) sealLocked(cause error) error {
	if !p.closed {
		if cause == nil {
			cause = cryptov4.ErrClosed
		}
		p.closed, p.cause = true, cause
		if p.relayBudget != nil {
			p.relayBudget.close()
		}
		p.reservation.Seal()
	}
	return p.cause
}

func (p *preparedCarrier) checkLocked() error {
	if p.closed {
		return p.cause
	}
	if p.activated {
		return cryptov4.ErrTransition
	}
	for _, err := range [...]error{p.parent.Err(), p.deadline.Check(), p.reservation.Check(), p.environment.Check(), p.shared.Check()} {
		if err != nil {
			return p.sealLocked(err)
		}
	}
	if err := p.checkGuaranteesLocked(); err != nil {
		return p.sealLocked(err)
	}
	return nil
}

func (p *preparedCarrier) checkGuaranteesLocked() error {
	actual, err := p.provider.ConnectionGuarantees()
	if err != nil {
		return err
	}
	if p.binding.Role == protocolv4.ServerToClient {
		actual.LocalConsumerTls13Verification = protocolv4.V4ConsumerTLS13VerificationNotApplicable
	}
	if actual != p.guarantees {
		return protocolv4.ErrRequiredGuaranteeUnavailable
	}
	return nil
}

func (p *PreparedCarrier) Check() error {
	if p == nil || p.preparedCarrier == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkLocked()
}

func (p *PreparedCarrier) check() error { return p.Check() }

// Admission calls these methods under its original gate. This owner never
// calls back into admission, so the lock order remains admission -> prepared.
func (p *PreparedCarrier) bindAdmission(admission *SessionAdmissionReservation) error {
	if p == nil || p.preparedCarrier == nil || admission == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	if p.admission != nil || p.relay {
		return cryptov4.ErrTransition
	}
	p.admission = admission
	return nil
}

func (p *PreparedCarrier) activate(admission *SessionAdmissionReservation) (io.ReadWriteCloser, InitialMessages, error) {
	if p == nil || p.preparedCarrier == nil || admission == nil {
		return nil, nil, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.admission != admission {
		return nil, nil, resourcev4.ErrOwner
	}
	if err := p.checkLocked(); err != nil {
		return nil, nil, err
	}
	if p.binding.Role == protocolv4.ServerToClient && p.guarantees.Scope == protocolv4.V4ConnectionGuaranteeScopeCompleteRelayPath && (!p.allowRegistered || !p.allowGranted) {
		return nil, nil, protocolv4.ErrHopAuthStage
	}
	p.activated = true
	// Connect cancellation no longer owns I/O after this handoff. Initial and
	// core retain their own original contexts and authorization/deadline gates.
	p.parent, p.deadline = nil, nil
	if p.binding.MessageCarrier {
		return nil, &p.messageAdapter, nil
	}
	return &p.streamAdapter, nil, nil
}

// Close only seals publication; physical provider methods run from admitted
// cleanup/initial/core callers outside the mutex, never on a new goroutine.
func (p *PreparedCarrier) Close() error {
	if p == nil || p.preparedCarrier == nil {
		return nil
	}
	p.mu.Lock()
	p.sealLocked(nil)
	p.mu.Unlock()
	return nil
}

// CloseError reports the original provider close result independently of
// physical cleanup completion. The result alone does not release any quota.
func (p *PreparedCarrier) CloseError() error {
	if p == nil || p.preparedCarrier == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeErr
}

func (p *preparedCarrier) closeProvider() error {
	p.mu.Lock()
	p.sealLocked(nil)
	if p.closing {
		p.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	if p.closeStarted {
		err := p.closeErr
		p.mu.Unlock()
		return err
	}
	p.closeStarted, p.closing = true, true
	provider := p.provider
	p.mu.Unlock()
	err := provider.Close()
	p.mu.Lock()
	p.closeErr, p.closing = err, false
	p.mu.Unlock()
	return err
}

func (p *PreparedCarrier) closeActivated(admission *SessionAdmissionReservation) error {
	if p == nil || p.preparedCarrier == nil || admission == nil {
		return resourcev4.ErrOwner
	}
	p.mu.Lock()
	valid := p.admission == admission && p.activated
	p.mu.Unlock()
	if !valid {
		return resourcev4.ErrOwner
	}
	return p.closeProvider()
}

// WaitCleanup has one admitted observer and no waiter queue. It drives physical
// Close through the same once dispatcher used by activated I/O, then joins the
// original provider. Cancellation never releases unfinished ownership.
func (p *PreparedCarrier) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if p == nil || p.preparedCarrier == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	if p.complete {
		p.mu.Unlock()
		return nil
	}
	if p.cleaning || p.closing || p.retiring {
		p.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	p.sealLocked(nil)
	p.cleaning = true
	provider := p.provider
	p.mu.Unlock()
	_ = p.closeProvider()
	err := provider.WaitCleanup(ctx)
	p.mu.Lock()
	p.cleaning = false
	if err == nil {
		if p.reading || p.writing || p.closing {
			err = cryptov4.ErrCapacity
		} else {
			p.complete = true
			clear(p.exporterValue[:])
			p.exporterArtifact, p.exporterReady = [32]byte{}, false
			p.parent, p.deadline = nil, nil
		}
	}
	p.mu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func (p *PreparedCarrier) Retire() error {
	if p == nil || p.preparedCarrier == nil {
		return nil
	}
	p.mu.Lock()
	if p.retired {
		p.mu.Unlock()
		return nil
	}
	if !p.complete || p.cleaning || p.closing || p.reading || p.writing || p.retiring {
		p.mu.Unlock()
		return resourcev4.ErrOwner
	}
	p.retiring = true
	provider := p.provider
	p.mu.Unlock()
	err := provider.Retire()
	p.mu.Lock()
	p.retiring = false
	if err == nil {
		p.retired = true
		p.provider, p.stream, p.messages, p.admission = nil, nil, nil, nil
		if p.relayBudget != nil {
			p.relayBudget.close()
		}
		p.reservation.Release()
		p.originalParent.giveBack(p.shared)
		p.shared, p.originalParent = resourcev4.Reference{}, nil
		p.originalReservation = resourcev4.Reference{}
	}
	p.mu.Unlock()
	return err
}

func (p *preparedCarrier) beginIO(writing bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.cause
	}
	if !p.activated {
		return cryptov4.ErrTransition
	}
	if err := p.reservation.Check(); err != nil {
		return p.sealLocked(err)
	}
	if err := p.shared.Check(); err != nil {
		return p.sealLocked(err)
	}
	if writing {
		if p.writing {
			return cryptov4.ErrCapacity
		}
		p.writing = true
	} else {
		if p.reading {
			return cryptov4.ErrCapacity
		}
		p.reading = true
	}
	return nil
}

func (p *preparedCarrier) endIO(writing bool) {
	p.mu.Lock()
	if writing {
		p.writing = false
	} else {
		p.reading = false
	}
	p.mu.Unlock()
}

func (s *preparedStream) Read(dst []byte) (int, error) {
	if err := s.owner.beginIO(false); err != nil {
		return 0, err
	}
	defer s.owner.endIO(false)
	return s.owner.meteredRead(dst)
}
func (s *preparedStream) Write(src []byte) (int, error) {
	if err := s.owner.beginIO(true); err != nil {
		return 0, err
	}
	defer s.owner.endIO(true)
	return s.owner.meteredWrite(src)
}
func (s *preparedStream) Close() error { return s.owner.closeProvider() }

func (m *preparedMessages) ReadMessage(ctx context.Context, dst []byte) (int, error) {
	if ctx == nil {
		return 0, cryptov4.ErrConfiguration
	}
	if err := m.owner.beginIO(false); err != nil {
		return 0, err
	}
	defer m.owner.endIO(false)
	return m.owner.meteredReadMessage(ctx, dst)
}
func (m *preparedMessages) WriteMessage(ctx context.Context, src []byte) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := m.owner.beginIO(true); err != nil {
		return err
	}
	defer m.owner.endIO(true)
	return m.owner.meteredWriteMessage(ctx, src)
}
func (m *preparedMessages) Close() error { return m.owner.closeProvider() }
