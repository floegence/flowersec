package sessionv4

import (
	"context"
	"crypto/rand"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
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
}

// PreparedCarrierConfig is fixed by trusted local preparation. Endpoint/TLS
// eligibility and bounded DNS/address attempts belong to that original caller.
// No activation credentials or post-spend authorization are required here.
type PreparedCarrierConfig struct {
	Candidate                protocolv4.PoolMember
	Attempt                  [16]byte
	Session                  protocolv4.ArtifactSessionParameters
	Role                     protocolv4.Direction
	Deadline                 *timev4.Deadline
	Reservation, Environment resourcev4.Reference
	RuntimeBytes             uint64
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

// PreparedCarrier is a copyable opaque handle. It exposes no unactivated I/O
// and starts no goroutine, timer, callback or cancellation observer. The existing
// Connect owner drives Check/Close and bounded cleanup until activation; the
// existing initial/core owner then drives the same original provider lifecycle.
type PreparedCarrier struct{ *preparedCarrier }

type preparedCarrier struct {
	mu                               sync.Mutex
	incarnation                      [16]byte
	binding                          PreparedCarrierBinding
	guarantees                       protocolv4.V4ConnectionGuarantees
	parent                           context.Context
	deadline                         *timev4.Deadline
	reservation, environment, shared resourcev4.Reference
	admission                        *SessionAdmissionReservation
	provider                         preparedProviderLifecycle
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
	shared, err := c.Environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := c.Reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	p := &preparedCarrier{incarnation: incarnation, binding: PreparedCarrierBinding{c.Candidate, c.Attempt, c.Session, c.Role, messages != nil}, guarantees: guarantees,
		parent: ctx, deadline: c.Deadline, reservation: owned, environment: c.Environment, shared: shared,
		provider: provider, stream: stream, messages: messages}
	p.streamAdapter.owner, p.messageAdapter.owner = p, p
	return &PreparedCarrier{p}, nil
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
	if p.admission != nil {
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
		p.reservation.Release()
		p.shared.Release()
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
	return s.owner.stream.Read(dst)
}
func (s *preparedStream) Write(src []byte) (int, error) {
	if err := s.owner.beginIO(true); err != nil {
		return 0, err
	}
	defer s.owner.endIO(true)
	return s.owner.stream.Write(src)
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
	return m.owner.messages.ReadMessage(ctx, dst)
}
func (m *preparedMessages) WriteMessage(ctx context.Context, src []byte) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := m.owner.beginIO(true); err != nil {
		return err
	}
	defer m.owner.endIO(true)
	return m.owner.messages.WriteMessage(ctx, src)
}
func (m *preparedMessages) Close() error { return m.owner.closeProvider() }
