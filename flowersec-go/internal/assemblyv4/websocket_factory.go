package assemblyv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// WebSocketFactoryConfig registers one immutable WSS route and numeric
// endpoint in the same Environment as Connect. Route is canonical public Route
// bytes, never an Artifact or activation credential. A distinct factory is
// required for a different route or trust policy. Roots are independent CA
// trust; pin-mode routes use their exact signed leaf-DER policy instead.
type WebSocketFactoryConfig struct {
	DialScope NativeDialScope
	// Role is the logical endpoint. Relay selects local physical role 2.
	// Tunnel routes require an independent deployment binding.
	Role          protocolv4.Direction
	Relay         bool
	RelayAccounts []resourcev4.Account
	Deployment    protocolv4.RelayDeploymentBinding
	Root          *resourcev4.Root
	Owner         resourcev4.OwnerKey
	Clock         *timev4.Clock
	Route         []byte
	RemoteAddress netip.AddrPort
	Roots         *x509.CertPool
	Origin        string
	// LocalBridgeToken enables only an exact signed numeric loopback route.
	LocalBridgeToken string
	Options          websocket.Options
	Connections      uint16
	RuntimeBytes     uint64
}

// WebSocketCarrierFactory admits each actual provider under the original
// preparation's tenant/Session accounts. There is no implicit DNS, retry,
// proxy, cookie, credential header, or TLS downgrade. Close fences new prepare
// calls; established carriers keep the borrowed immutable policy until their
// original owners retire them. WaitCleanup does not close those Sessions.
type WebSocketCarrierFactory struct {
	parentSet           *CarrierSet
	mu                  sync.Mutex
	c                   WebSocketFactoryConfig
	document            *protocolv4.Document
	routeBinding        protocolv4.CarrierRouteBinding
	policy              tlspolicy.Policy
	host, endpoint      string
	subprotocol         string
	localLoopback       bool
	reservation, shared resourcev4.Reference
	environment         resourcev4.Reference
	providerCharge      resourcev4.Vector
	slots               []webSocketFactorySlot
	serial              uint64
	closed, cleaned     bool
	done                chan struct{}
}

type webSocketFactorySlot = carrierFactorySlot

const webSocketFactoryRouteBytes = 16384
const webSocketFactoryRouteNodes = 1024

func WebSocketCarrierFactoryCharge(c WebSocketFactoryConfig) (resourcev4.Vector, error) {
	if len(c.RelayAccounts) > resourcev4.MaxAccountsPerCharge || !c.Relay && len(c.RelayAccounts) != 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if c.Root == nil || c.Clock == nil || len(c.Route) == 0 || len(c.Route) > webSocketFactoryRouteBytes ||
		!c.RemoteAddress.IsValid() || c.RemoteAddress.Port() == 0 || c.RemoteAddress.Addr().Zone() != "" ||
		c.Connections == 0 || c.Connections > 1024 || c.RuntimeBytes == 0 || len(c.Origin) > 1024 || len(c.LocalBridgeToken) > 1024 || strings.ContainsAny(c.LocalBridgeToken, "\r\n") {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := websocket.Charge(c.Options); err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(webSocketFactoryRouteBytes, webSocketFactoryRouteNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	perSlot := uint64(unsafe.Sizeof(webSocketFactorySlot{})) + uint64(unsafe.Sizeof(factoryWebSocket{})) + uint64(unsafe.Sizeof(factoryPreparation{})) + native.EnvironmentBorrowBytes() + tlspolicy.BackingBytes() + 4096
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(WebSocketCarrierFactory{})) + uint64(len(c.RelayAccounts))*uint64(unsafe.Sizeof(resourcev4.Account{})) + decoder + 4096 + uint64(c.Connections)*perSlot,
		resourcev4.Items: 3*uint64(c.Connections) + 1, resourcev4.WorkSlots: uint64(c.Connections), resourcev4.Tasks: uint64(c.Connections)}).
		Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewWebSocketCarrierFactory(c WebSocketFactoryConfig, reservation, environment resourcev4.Reference) (_ *WebSocketCarrierFactory, err error) {
	charge, err := WebSocketCarrierFactoryCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckRoot(c.Root); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	c.RelayAccounts = append([]resourcev4.Account(nil), c.RelayAccounts...)
	factory := &WebSocketCarrierFactory{c: c, reservation: owned, environment: environment, done: make(chan struct{})}
	defer func() {
		if err != nil {
			factory.Close()
		}
	}()
	factory.shared, err = environment.Borrow()
	if err != nil {
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(webSocketFactoryRouteBytes, webSocketFactoryRouteNodes)
	if err != nil {
		return nil, err
	}
	factory.document, err = decoder.DecodeMap(c.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	leg, binding, err := factory.document.BindCarrierRoute(c.Role, c.Relay, false, 1, c.Deployment)
	if err != nil {
		return nil, err
	}
	factory.routeBinding = binding
	pathKind, _ := factory.document.Root().Named("Route", "path_kind").Uint()
	host, _ := leg.Named("Leg", "host").Text()
	port, _ := leg.Named("Leg", "port").Uint()
	path, _ := leg.Named("Leg", "path").Text()
	subprotocol, _ := leg.Named("Leg", "subprotocol").Text()
	access, _ := leg.Named("Leg", "access_class").Uint()
	factory.localLoopback = access == 1
	wantPath, wantProtocol := "/flowersec/v4/direct", websocket.SubprotocolDirect
	if pathKind == 1 {
		wantPath, wantProtocol = "/flowersec/v4/tunnel", websocket.SubprotocolTunnel
	}
	if factory.localLoopback {
		wantPath, wantProtocol = "/flowersec/v4/local", websocket.SubprotocolLocal
	}
	alpn, _ := leg.Named("Leg", "alpn").Text()
	if host == "" || port != uint64(c.RemoteAddress.Port()) || path != wantPath || subprotocol != wantProtocol || !factory.localLoopback && alpn != "http/1.1" {
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && address != c.RemoteAddress.Addr() {
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	if factory.localLoopback {
		numeric, parseErr := netip.ParseAddr(host)
		origin, _ := leg.Named("Leg", "origin").Text()
		if parseErr != nil || !numeric.IsLoopback() || numeric != c.RemoteAddress.Addr() || c.Roots != nil || c.LocalBridgeToken == "" || c.Origin != "http://"+c.RemoteAddress.String() || origin != c.Origin || c.Relay || pathKind != 0 {
			return nil, protocolv4.CBORFailure("carrier_binding_invalid")
		}
	} else {
		if c.LocalBridgeToken != "" {
			return nil, resourcev4.ErrConfiguration
		}
		originPolicy := leg.Named("Leg", "origin_policy")
		if originPolicy.Encoded() != nil {
			allowed, _ := originPolicy.Named("OriginPolicy", "allow_absent").Bool()
			if c.Origin != "" {
				allowed = false
				origins := originPolicy.Named("OriginPolicy", "origins")
				for index := range origins.Len() {
					origin, _ := origins.Index(index).Text()
					allowed = allowed || origin == c.Origin
				}
			}
			if !allowed {
				return nil, protocolv4.CBORFailure("carrier_binding_invalid")
			}
		} else if c.Origin != "" {
			return nil, protocolv4.CBORFailure("carrier_binding_invalid")
		}
		factory.policy, err = tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
		if err != nil {
			return nil, err
		}
		if factory.policy.RequiresRoots() && c.Roots == nil || !factory.policy.RequiresRoots() && c.Roots != nil {
			return nil, resourcev4.ErrConfiguration
		}
	}
	factory.host, factory.subprotocol = host, subprotocol
	scheme := "wss://"
	if factory.localLoopback {
		scheme = "ws://"
	}
	factory.endpoint = scheme + net.JoinHostPort(host, strconv.FormatUint(port, 10)) + path
	factory.c.Route = nil // The admitted decoder owns the only retained copy.
	factory.c.Origin = strings.Clone(c.Origin)
	factory.c.LocalBridgeToken = strings.Clone(c.LocalBridgeToken)
	// The CA pool is an independently admitted immutable dependency, just as in
	// the native provider. Clone its index so caller additions cannot widen it.
	if c.Roots != nil {
		factory.c.Roots = c.Roots.Clone()
	}
	factory.providerCharge, err = websocket.Charge(c.Options)
	if err != nil {
		return nil, err
	}
	factory.slots = make([]webSocketFactorySlot, c.Connections)
	return factory, nil
}

func (factory *WebSocketCarrierFactory) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	return factory.prepareCarrier(ctx, request, nil)
}

func (factory *WebSocketCarrierFactory) prepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest, preparation *factoryPreparation) (_ *sessionv4.PreparedCarrier, err error) {
	if factory == nil || ctx == nil || request.Config.Deadline == nil || request.Config.Role != factory.c.Role ||
		request.Budget.PreauthBytes == 0 || request.Budget.PreauthBytes > 262144 || request.Budget.WorkUnits == 0 ||
		!request.Config.Deadline.BelongsTo(factory.c.Clock) || !request.Config.Session.Contract.Valid() ||
		request.Config.Session.ArtifactDigest == ([32]byte{}) || request.Config.Attempt == ([16]byte{}) ||
		request.Config.Candidate.Index >= 16 || request.Config.Candidate.CandidateID == ([16]byte{}) ||
		request.Config.Candidate.RouteDigest == ([32]byte{}) || request.Config.Reservation == request.Config.Environment ||
		uint64(factory.c.Options.MaxMessageBytes) < uint64(request.Config.Session.Contract.Limits().MaxFrame)+protocolv4.EnvelopePrefixSize {
		return nil, resourcev4.ErrConfiguration
	}
	if _, err = protocolv4.Profile(request.Config.Session.Profile); err != nil {
		return nil, err
	}
	if _, err = sessionv4.PreparedCarrierCharge(request.Config.RuntimeBytes); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = request.Config.Deadline.Check(); err != nil {
		return nil, err
	}
	if err = request.Config.Reservation.CheckSameEnvironment(factory.reservation); err != nil {
		return nil, err
	}
	accounts := []resourcev4.Account{request.Scope.Tenant, request.Scope.Session}
	if factory.c.Relay && len(factory.c.RelayAccounts) > 0 {
		accounts = factory.c.RelayAccounts
	}
	if err = request.Config.Reservation.CheckAllocationScope(factory.c.Root, factory.c.Owner, accounts); err != nil {
		return nil, err
	}
	if err = request.Config.Environment.CheckSameEnvironment(factory.environment); err != nil {
		return nil, err
	}
	factory.mu.Lock()
	if factory.closed || preparation == nil && factory.serial == math.MaxUint64 {
		factory.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	if !bytes.Equal(request.Route, factory.document.Bytes()) {
		factory.mu.Unlock()
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	if err = factory.document.MatchCandidateRoute(request.Config.Candidate); err != nil {
		factory.mu.Unlock()
		return nil, err
	}
	if request.AddressAttempt != 0 {
		factory.mu.Unlock()
		return nil, native.ErrAddressesExhausted
	}
	slot, serial, floor, err := claimFactorySlot(factory, factory.slots, &factory.serial, preparation, request)
	if err != nil {
		factory.mu.Unlock()
		return nil, err
	}
	providerEnvironment := factory.slots[slot].providerEnvironment
	factory.mu.Unlock()
	transferred := false
	defer func() {
		if !transferred {
			factory.release(slot, serial)
		}
	}()
	remaining, err := request.Config.Deadline.RemainingMS()
	if err != nil {
		return nil, err
	}
	limit := factory.c.Options.HandshakeTimeout
	if remaining < uint64(limit/time.Millisecond) {
		limit = time.Duration(remaining) * time.Millisecond
	}
	// The native provider's original timer enforces this shorter preparation
	// cap. Do not add an unjoined context deadline callback around it.
	prepareCtx, cancelCause := newCarrierPreparationContext(ctx)
	cancel := func() { cancelCause(context.Canceled) }
	defer cancel()
	factory.mu.Lock()
	closed := factory.closed
	factory.slots[slot].cancel = cancel
	factory.mu.Unlock()
	if closed {
		cancel()
		return nil, resourcev4.ErrClosed
	}
	// The factory's admitted task owns parent cancellation and joins before
	// the original candidate position can be reused. The provider keeps its
	// existing socket deadline; this observer needs no additional timer.
	stop, stopped := make(chan struct{}), make(chan struct{})
	go watchCarrierPreparation(ctx, prepareCtx, cancelCause, nil, stop, stopped)
	watching := true
	finishWatch := func() {
		if watching {
			watching = false
			close(stop)
			<-stopped
		}
	}
	defer finishWatch()
	var identity [56]byte
	copy(identity[:16], factory.c.Owner.Backing[:])
	copy(identity[16:32], request.Config.Attempt[:])
	copy(identity[32:48], "wss-provider-v4")
	binary.BigEndian.PutUint64(identity[48:], serial)
	digest := sha256.Sum256(identity[:])
	owner := factory.c.Owner
	copy(owner.Backing[:], digest[:16])
	var reservation resourcev4.Reference
	if floor != nil {
		reservation, err = floor.Checkout()
	} else {
		reservation, err = factory.c.Root.Reserve(owner, factory.providerCharge, accounts...)
	}
	if err != nil {
		return nil, err
	}
	// Dial takes this reservation only after its own input checks. Release is
	// harmless after Take, and necessary on an earlier refusal.
	defer reservation.Release()
	now, err := factory.c.Clock.Sample()
	if err != nil {
		return nil, err
	}
	var policy tlspolicy.Prepared
	if !factory.localLoopback {
		policy, err = factory.policy.Prepare(now.Interval)
		if err != nil {
			return nil, err
		}
	}
	provider := &factoryWebSocket{factory: factory, slot: slot, serial: serial}
	deadline := request.Config.Deadline
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: factory.host, InsecureSkipVerify: true, SessionTicketsDisabled: true}
	// Verification is complete and independent inside this mandatory callback:
	// either CA+logical hostname or the original active signed leaf-DER set.
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if err := deadline.Check(); err != nil {
			return err
		}
		sample, err := factory.c.Clock.Sample()
		if err != nil {
			return err
		}
		provider.verification, err = policy.Verify(state, factory.host, factory.c.Roots, sample.Interval)
		return err
	}
	if factory.localLoopback {
		tlsConfig = nil
	}
	header := make(http.Header)
	if factory.c.Origin != "" {
		header.Set("Origin", factory.c.Origin)
	}
	if factory.localLoopback {
		header.Set("X-Flowersec-Private-Bridge-Token", factory.c.LocalBridgeToken)
	}
	options := factory.c.Options
	options.HandshakeTimeout = limit
	defer func() {
		if !transferred && provider.Messages != nil {
			_ = provider.Messages.Close()
			_ = provider.Messages.WaitCleanup(context.Background())
			_ = provider.Messages.Retire()
		}
	}()
	err = RunNativeDial(prepareCtx, factory.c.DialScope, func() error {
		provider.Messages, err = websocket.Dial(prepareCtx, websocket.DialConfig{
			URL: factory.endpoint, RemoteAddress: factory.c.RemoteAddress, Subprotocol: factory.subprotocol,
			TLSConfig: tlsConfig, Header: header, PrepareBytes: request.Budget.PreauthBytes,
			CheckPolicy: func(actual *url.URL, address netip.AddrPort, actualHeader http.Header) error {
				if actual.String() != factory.endpoint || address != factory.c.RemoteAddress || !factory.checkHeaders(actualHeader) {
					return protocolv4.CBORFailure("carrier_binding_invalid")
				}
				return deadline.Check()
			},
		}, options, reservation, request.Config.Environment, providerEnvironment)
		return err
	})
	if err != nil {
		return nil, err
	}
	prepare := sessionv4.NewPreparedMessages
	if factory.c.Relay {
		prepare = sessionv4.NewPreparedRelayMessages
	}
	prepared, err := prepare(ctx, request.Config, provider)
	if err != nil {
		return nil, err
	}
	finishWatch()
	transferred = true
	factory.mu.Lock()
	factory.slots[slot].cancel = nil
	closed = factory.closed
	factory.mu.Unlock()
	if closed {
		return prepared, resourcev4.ErrClosed
	}
	return prepared, context.Cause(prepareCtx)
}

func (factory *WebSocketCarrierFactory) checkHeaders(header http.Header) bool {
	if !factory.localLoopback {
		return sameWebSocketOrigin(header, factory.c.Origin)
	}
	return len(header) == 2 && len(header.Values("Origin")) == 1 && header.Get("Origin") == factory.c.Origin && len(header.Values("X-Flowersec-Private-Bridge-Token")) == 1 && header.Get("X-Flowersec-Private-Bridge-Token") == factory.c.LocalBridgeToken
}

func sameWebSocketOrigin(header http.Header, origin string) bool {
	if origin == "" {
		return len(header) == 0
	}
	return len(header) == 1 && len(header.Values("Origin")) == 1 && header.Get("Origin") == origin
}

func (factory *WebSocketCarrierFactory) release(index int, serial uint64) {
	factory.mu.Lock()
	if index >= 0 && index < len(factory.slots) {
		factory.slots[index].release(serial)
	}
	factory.cleanupLocked()
	factory.mu.Unlock()
	if factory.parentSet != nil {
		factory.parentSet.providerReturned()
	}
}

func (factory *WebSocketCarrierFactory) cleanupLocked() {
	if !factory.closed || factory.cleaned {
		return
	}
	for _, slot := range factory.slots {
		if slot.active {
			return
		}
	}
	factory.cleaned = true
	if factory.document != nil {
		factory.document.Release()
		factory.document = nil
	}
	factory.c.Roots = nil
	factory.c.Route = nil
	factory.slots = nil
	factory.shared.Release()
	factory.reservation.Release()
	close(factory.done)
}

func (factory *WebSocketCarrierFactory) Close() {
	if factory == nil {
		return
	}
	factory.mu.Lock()
	factory.closed = true
	factory.mu.Unlock()
	for index := 0; ; index++ {
		factory.mu.Lock()
		if index >= len(factory.slots) {
			factory.mu.Unlock()
			break
		}
		cancel := factory.slots[index].cancel
		factory.slots[index].closeAdmission()
		factory.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
	factory.mu.Lock()
	factory.cleanupLocked()
	factory.mu.Unlock()
}

func (factory *WebSocketCarrierFactory) WaitCleanup(ctx context.Context) error {
	if factory == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-factory.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type factoryWebSocket struct {
	*websocket.Messages
	factory      *WebSocketCarrierFactory
	slot         int
	serial       uint64
	verification tlspolicy.Verification
	once         sync.Once
}

func (provider *factoryWebSocket) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	now, err := provider.factory.c.Clock.Sample()
	if err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	if !provider.factory.localLoopback {
		if err = provider.verification.Check(now.Interval); err != nil {
			return protocolv4.V4ConnectionGuarantees{}, err
		}
	}
	actual, err := provider.Messages.ConnectionGuarantees()
	if err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	return provider.factory.routeBinding.Check(actual)
}

func (provider *factoryWebSocket) Retire() error {
	if err := provider.Messages.Retire(); err != nil {
		return err
	}
	provider.once.Do(func() { provider.factory.release(provider.slot, provider.serial) })
	return nil
}

var _ sessionv4.ConsumerCarrierFactory = (*WebSocketCarrierFactory)(nil)

// A single fixed endpoint has one useful preparation lane per Connect. Other
// Sessions retain their independent slots from the same finite factory table.
func (factory *WebSocketCarrierFactory) PreparationParallelism() uint8 {
	if factory == nil {
		return 0
	}
	return 1
}

func (factory *WebSocketCarrierFactory) AdmitPreparation(request sessionv4.CarrierPreparationAdmissionRequest) (sessionv4.CarrierPreparation, error) {
	if factory == nil || request.Clock == nil {
		return nil, resourcev4.ErrConfiguration
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.closed {
		return nil, resourcev4.ErrClosed
	}
	if request.Clock != factory.c.Clock {
		return nil, resourcev4.ErrOwner
	}
	preparation, err := admitFactoryPreparation(factory, factory.slots, &factory.serial, factory.c.Root, factory.c.Owner,
		factory.reservation, factory.environment, factory.providerCharge, request)
	if err != nil {
		return nil, err
	}
	return preparation, nil
}

func (factory *WebSocketCarrierFactory) checkPreparation(index int, serial uint64) error {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.closed {
		return resourcev4.ErrClosed
	}
	slot, err := originalFactorySlot(factory.slots, index, serial)
	if err != nil {
		return err
	}
	if slot.closing {
		return resourcev4.ErrClosed
	}
	if err = slot.policy.Check(); err != nil {
		return err
	}
	if err = slot.providerEnvironment.Check(slot.environment); err != nil {
		return err
	}
	return slot.floor.CheckAvailable()
}

func (factory *WebSocketCarrierFactory) closePreparation(index int, serial uint64) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if slot, err := originalFactorySlot(factory.slots, index, serial); err == nil {
		slot.closeAdmission()
	}
	factory.cleanupLocked()
}

var _ sessionv4.AdmittingConsumerCarrierFactory = (*WebSocketCarrierFactory)(nil)

// The fixed endpoint has exactly one useful candidate position per source.
func (factory *WebSocketCarrierFactory) AdmitPreparations(request sessionv4.CarrierPreparationAdmissionRequest, output []sessionv4.CarrierPreparation) error {
	if len(output) != 1 || output[0] != nil {
		return resourcev4.ErrConfiguration
	}
	preparation, err := factory.AdmitPreparation(request)
	output[0] = preparation
	return err
}

func (factory *WebSocketCarrierFactory) attachSet(set *CarrierSet) { factory.parentSet = set }

func (factory *WebSocketCarrierFactory) setView() carrierSetFactory {
	return carrierSetFactory{owner: factory, mu: &factory.mu, document: &factory.document, closed: &factory.closed, slots: &factory.slots, serial: &factory.serial, reservation: factory.reservation, environment: factory.environment, clock: factory.c.Clock}
}
