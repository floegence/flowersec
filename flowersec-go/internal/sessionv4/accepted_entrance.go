package sessionv4

import (
	"context"
	"io"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// AcceptedEntranceConfig is the Acceptor's fixed local entrance policy, before
// remote material is trusted. Its frame capacity must accommodate the complete
// signed frame contract; negotiation can tighten but never enlarge that cap.
// This direct listener is the logical server. Tunnel hop admission is separate.
type AcceptedEntranceConfig struct {
	Initial                                                InitialConfig
	RuntimeBytes, InitialRuntimeBytes, CarrierRuntimeBytes uint64
}

// AcceptedRouteVerifier belongs to the actual accepted provider, not material
// lookup. It must compare the signed candidate with its immutable observed
// listener, transport, TLS, Origin and deployment policy and bind HelloPolicy
// to that carrier. This is bounded local work, without I/O or user callbacks;
// any policy storage is preadmitted in the same Environment. Its actual method
// tail is retained by the entrance even when Close wins concurrently.
type AcceptedRouteVerifier interface {
	CheckAcceptedRoute(*protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error
}

// AcceptedEntrance owns one accepted provider and its preauth Initial through
// actual cleanup. It has no Session slot, spend authority or Noise permission.
// Material lookup and verification run in the existing Acceptor work position.
type AcceptedEntrance struct {
	host                                                        *EnvironmentSession
	mu                                                          sync.Mutex
	initial                                                     *InitialExchange
	carrier                                                     *PreparedCarrier
	listener                                                    AcceptedRouteVerifier
	owner, environment, initialBacking                          resourcev4.Reference
	config                                                      AcceptedEntranceConfig
	guard                                                       acceptedAuthorization
	admission                                                   *SessionAdmissionReservation
	busy, closed, closing, cleaning, cleaned, retiring, retired bool
	wake, done                                                  chan struct{}
}

// This gate deliberately begins as local preauth admission. Only adoption by
// the original Session token installs actual endpoint authority; only its
// definite original admitted continuation opens FSA/Noise. The same guard is
// retained by Initial and the Engine, so no watchdog switch loses revocation.
type acceptedAuthorization struct {
	mu                       sync.Mutex
	reservation, environment resourcev4.Reference
	deadline                 *timev4.Deadline
	authorization            *protocolv4.EndpointAuthorization
	application              *ApplicationLease
	owner                    *SessionAdmissionReservation
	admitted                 bool
	admissionBinding         [32]byte
	serverEpoch              uint64
	reservationKey           [32]byte
	terminal                 error
	wake                     chan struct{}
}

func acceptedEntranceCharges(c AcceptedEntranceConfig) (metadata, initial, carrier resourcev4.Vector, err error) {
	if c.RuntimeBytes == 0 || c.InitialRuntimeBytes == 0 || c.Initial.Role != protocolv4.ServerToClient || c.Initial.Deadline == nil || c.Initial.Authorization != nil || c.Initial.Reservation != (resourcev4.Reference{}) || c.Initial.accepted != nil || c.Initial.original.enabled || c.Initial.ActivationSourceProfile != "live_authority" && c.Initial.ActivationSourceProfile != "preauthorized_pool" {
		return metadata, initial, carrier, cryptov4.ErrConfiguration
	}
	if _, err = protocolv4.Profile(c.Initial.Profile); err != nil {
		return
	}
	metadata, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(AcceptedEntrance{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	initial, err = InitialCharge(c.Initial.Limits)
	if err == nil {
		initial, err = initial.Add(resourcev4.Vector{resourcev4.SDKBytes: c.InitialRuntimeBytes})
	}
	if err == nil {
		carrier, err = PreparedCarrierCharge(c.CarrierRuntimeBytes)
	}
	return
}

func AcceptedEntranceRequirements(c AcceptedEntranceConfig) (resourcev4.Vector, error) {
	meta, initial, carrier, err := acceptedEntranceCharges(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	total, err := meta.Add(initial)
	if err == nil {
		total, err = total.Add(carrier)
	}
	return total, err
}

func NewAcceptedStream(ctx context.Context, c AcceptedEntranceConfig, stream io.ReadWriteCloser, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts ...resourcev4.Account) (*AcceptedEntrance, error) {
	provider, ok := stream.(preparedProviderLifecycle)
	if !ok || stream == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return newAcceptedEntrance(ctx, c, provider, stream, nil, root, owner, environment, accounts)
}

func NewAcceptedMessages(ctx context.Context, c AcceptedEntranceConfig, messages InitialMessages, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts ...resourcev4.Account) (*AcceptedEntrance, error) {
	provider, ok := messages.(preparedProviderLifecycle)
	if !ok || messages == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return newAcceptedEntrance(ctx, c, provider, nil, messages, root, owner, environment, accounts)
}

// Success owns the provider; failure leaves it with its caller. All capacity
// and Environment references are acquired before constructing Initial/tasks.
func newAcceptedEntrance(ctx context.Context, c AcceptedEntranceConfig, provider preparedProviderLifecycle, stream io.ReadWriteCloser, messages InitialMessages, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts []resourcev4.Account) (_ *AcceptedEntrance, err error) {
	listener, ok := provider.(AcceptedRouteVerifier)
	if ctx == nil || root == nil || !ok {
		return nil, cryptov4.ErrConfiguration
	}
	meta, initial, carrier, err := acceptedEntranceCharges(c)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = c.Initial.Deadline.Check(); err != nil {
		return nil, err
	}
	if err = provider.CheckEnvironment(environment); err != nil {
		return nil, err
	}
	guarantees, err := provider.ConnectionGuarantees()
	if err != nil {
		return nil, err
	}
	if !guarantees.Valid() {
		return nil, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	// A direct listener cannot observe the remote consumer's TLS controls.
	guarantees.LocalConsumerTls13Verification = protocolv4.V4ConsumerTLS13VerificationNotApplicable
	var refs [3]resourcev4.Reference
	requests := [3]resourcev4.Request{{Owner: admissionResourceKey(owner, 0), Charge: meta, Accounts: accounts}, {Owner: admissionResourceKey(owner, 1), Charge: initial, Accounts: accounts}, {Owner: admissionResourceKey(owner, 2), Charge: carrier, Accounts: accounts}}
	if err = root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	if err = refs[0].CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			shared.Release()
		}
	}()
	backing, err := refs[1].Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			backing.Release()
		}
	}()
	owned, err := refs[0].Take(meta)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			owned.Release()
		}
	}()
	transport, err := refs[2].Take(carrier)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			transport.Release()
		}
	}()
	e := &AcceptedEntrance{owner: owned, environment: environment, initialBacking: backing, listener: listener, config: c, wake: make(chan struct{}, 1), done: make(chan struct{})}
	e.guard = acceptedAuthorization{reservation: owned, environment: environment, deadline: c.Initial.Deadline, wake: make(chan struct{}, 1)}
	p := &preparedCarrier{binding: PreparedCarrierBinding{Role: protocolv4.ServerToClient, MessageCarrier: messages != nil}, guarantees: guarantees, reservation: transport, environment: environment, shared: shared, provider: provider, stream: stream, messages: messages, activated: true}
	p.streamAdapter.owner, p.messageAdapter.owner = p, p
	e.carrier = &PreparedCarrier{p}
	config := c.Initial
	config.Authorization, config.Reservation, config.accepted = &e.guard, refs[1], &e.guard
	if messages != nil {
		e.initial, err = NewInitialMessages(ctx, config, &p.messageAdapter)
	} else {
		e.initial, err = NewInitialStream(ctx, config, &p.streamAdapter)
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (g *acceptedAuthorization) checkLocked() error {
	if g.terminal != nil {
		return g.terminal
	}
	if err := g.reservation.Check(); err != nil {
		return err
	}
	if err := g.environment.Check(); err != nil {
		return err
	}
	if g.application != nil {
		if err := g.application.Check(); err != nil {
			return err
		}
	}
	if g.authorization != nil {
		return g.authorization.Check()
	}
	return g.deadline.Check()
}
func (g *acceptedAuthorization) Check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checkLocked()
}
func (g *acceptedAuthorization) RemainingMS() (uint64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.checkLocked(); err != nil {
		return 0, err
	}
	if g.authorization != nil {
		return g.authorization.RemainingMS()
	}
	return g.deadline.RemainingMS()
}
func (g *acceptedAuthorization) Wake() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.authorization != nil {
		return g.authorization.Wake()
	}
	return g.wake
}
func (g *acceptedAuthorization) Notify() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.authorization != nil {
		g.authorization.Notify()
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *acceptedAuthorization) Close(cause error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cause == nil {
		cause = cryptov4.ErrClosed
	}
	if g.terminal == nil {
		g.terminal = cause
	}
	if g.authorization != nil {
		g.authorization.Close(cause)
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *acceptedAuthorization) checkAdmitted() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.checkLocked(); err != nil {
		return err
	}
	if !g.admitted {
		return ErrAdmissionRejected
	}
	return nil
}

// A verified original entrance may send a signed rejection without acquiring
// an admitted continuation. This never permits an admitted FSA or Noise.
func (g *acceptedAuthorization) checkResponse(admitted bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.checkLocked(); err != nil {
		return err
	}
	if g.owner == nil || g.authorization == nil || admitted && !g.admitted {
		return ErrAdmissionRejected
	}
	_, err := g.authorization.CheckAdmission()
	return err
}

func (g *acceptedAuthorization) matchResponse(response protocolv4.AdmissionResponse) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if response.Admitted && (!g.admitted || response.AdmissionBinding != g.admissionBinding || response.ServerEpoch != g.serverEpoch || response.ReservationKey != g.reservationKey) {
		return protocolv4.CBORFailure("admission_response_binding")
	}
	return nil
}

func (g *acceptedAuthorization) matchResponseDocument(doc *protocolv4.Document) error {
	get := func(name string) protocolv4.Value { return doc.Root().Named("FSA4", name) }
	status, _ := get("status").Uint()
	if status != 0 {
		return nil
	}
	epoch, _ := get("server_epoch").Uint()
	key, _ := get("reservation_key").ByteString()
	binding, _ := get("admission_binding").ByteString()
	return g.matchResponse(protocolv4.AdmissionResponse{Admitted: true, ServerEpoch: epoch, ReservationKey: [32]byte(key), AdmissionBinding: [32]byte(binding)})
}

func (e *AcceptedEntrance) begin() (*InitialExchange, error) {
	return e.beginHosted(nil)
}

func (e *AcceptedEntrance) beginHosted(host *EnvironmentSession) (*InitialExchange, error) {
	if e == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if e.busy || e.admission != nil || e.host != host {
		return nil, cryptov4.ErrTransition
	}
	if err := e.owner.Check(); err != nil {
		return nil, err
	}
	e.busy = true
	return e.initial, nil
}
func (e *AcceptedEntrance) end() { e.mu.Lock(); e.busy = false; e.signalLocked(); e.mu.Unlock() }
func (e *AcceptedEntrance) signalLocked() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// ReadClientHello exposes only the original bounded bytes for trusted local
// material lookup. The lookup result still requires full signature/trust checks.
func (e *AcceptedEntrance) ReadClientHello(dst []byte) (int, error) {
	return e.readClientHello(dst, nil)
}

func (e *AcceptedEntrance) readClientHello(dst []byte, host *EnvironmentSession) (int, error) {
	x, err := e.beginHosted(host)
	if err != nil {
		return 0, err
	}
	defer e.end()
	if err = x.Receive(protocolv4.FrameNegotiate, func([]byte) error { return nil }); err != nil {
		return 0, err
	}
	return x.CopyClientHello(dst)
}

func (e *AcceptedEntrance) Negotiate(hello InitialHello) (*protocolv4.HelloBinding, error) {
	return e.negotiate(hello, nil)
}

func (e *AcceptedEntrance) negotiate(hello InitialHello, host *EnvironmentSession) (*protocolv4.HelloBinding, error) {
	x, err := e.beginHosted(host)
	if err != nil {
		return nil, err
	}
	defer e.end()
	session, err := hello.Artifact.SessionParameters()
	if err != nil {
		return nil, err
	}
	x.mu.Lock()
	if err = x.checkLocked(); err == nil && (x.phase != 1 || x.sending || x.receiving || hello.Workspace == nil || session.Profile != x.config.Profile || int(session.Contract.Limits().MaxFrame) > x.config.Limits.MaxFrame) {
		err = cryptov4.ErrConfiguration
	}
	if err == nil {
		x.config.Limits.MaxFrame = int(session.Contract.Limits().MaxFrame)
	}
	x.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err = hello.Artifact.CheckDirectListenerCandidate(hello.Index); err != nil {
		return nil, err
	}
	if err = e.listener.CheckAcceptedRoute(hello.Artifact, hello.Index, hello.Policy); err != nil {
		return nil, err
	}
	if err = hello.Artifact.CheckDirectConnectionGuarantees(hello.Index, protocolv4.ServerToClient, e.carrier.guarantees); err != nil {
		return nil, err
	}
	return x.negotiateServerRetained(hello)
}

// ReceiveAdmission keeps the original receive/verify position until return.
// A verified SignedMap must subsequently match these exact retained wire facts
// when the Session token adopts this entrance before the durable reserve/CAS.
func (e *AcceptedEntrance) ReceiveAdmission(verify func([]byte) error) error {
	return e.receiveAdmission(verify, nil)
}

func (e *AcceptedEntrance) receiveAdmission(verify func([]byte) error, host *EnvironmentSession) error {
	x, err := e.beginHosted(host)
	if err != nil {
		return err
	}
	defer e.end()
	return x.Receive(protocolv4.FrameAdmission, verify)
}

func (e *AcceptedEntrance) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.closing = true
	e.owner.Seal()
	x, p := e.initial, e.carrier
	e.signalLocked()
	e.mu.Unlock()
	x.Close(cryptov4.ErrClosed)
	_ = p.Close()
	e.mu.Lock()
	e.closing = false
	e.signalLocked()
	e.mu.Unlock()
}

func (e *AcceptedEntrance) WaitCleanup(ctx context.Context) (err error) {
	if e == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	for {
		e.mu.Lock()
		if e.cleaned {
			e.mu.Unlock()
			return nil
		}
		if !e.closed {
			e.mu.Unlock()
			return cryptov4.ErrTransition
		}
		if !e.busy && !e.cleaning && !e.closing {
			e.cleaning = true
			e.mu.Unlock()
			break
		}
		e.mu.Unlock()
		select {
		case <-e.wake:
		case <-e.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	defer func() {
		e.mu.Lock()
		e.cleaning = false
		if err == nil {
			e.cleaned = true
			close(e.done)
		}
		e.signalLocked()
		e.mu.Unlock()
	}()
	if err = e.initial.WaitCleanup(ctx); err != nil {
		return err
	}
	return e.carrier.WaitCleanup(ctx)
}

func (e *AcceptedEntrance) Retire() error { return e.retireAdmission(nil) }

func (e *AcceptedEntrance) retireAdmission(admission *SessionAdmissionReservation) error {
	if e == nil {
		return cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	if e.retired {
		e.mu.Unlock()
		return nil
	}
	if !e.cleaned || e.cleaning || e.busy || e.closing || e.retiring || e.admission != admission {
		e.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	e.retiring = true
	p := e.carrier
	e.mu.Unlock()
	err := p.Retire()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.retiring = false
	if err != nil {
		return err
	}
	e.initial, e.carrier, e.admission = nil, nil, nil
	e.listener = nil
	e.host = nil
	e.config = AcceptedEntranceConfig{}
	e.initialBacking.Release()
	e.initialBacking, e.environment = resourcev4.Reference{}, resourcev4.Reference{}
	e.guard.mu.Lock()
	e.guard.deadline, e.guard.owner, e.guard.authorization, e.guard.application = nil, nil, nil, nil
	e.guard.mu.Unlock()
	e.retired = true
	e.owner.Release()
	e.owner = resourcev4.Reference{}
	return nil
}
