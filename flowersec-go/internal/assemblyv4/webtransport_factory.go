package assemblyv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// WebTransportFactoryConfig binds one direct or tunnel route to an already selected numeric UDP
// endpoint. Roots are independently trusted immutable CA backing; pin mode
// accepts only the exact signed leaf-DER policy. No source or credential is
// available to the factory, and preparation sends no Flowersec bytes.
type WebTransportFactoryConfig struct {
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
	Origin        string
	Roots         *x509.CertPool
	Options       webtransport.OwnedOptions
	Connections   uint16
	RuntimeBytes  uint64
}

// WebTransportCarrierFactory retains policy and one fixed position per actual provider.
// Its Close cancels preparation only; an established original Session retains
// its provider and shared factory backing until physical retirement.
type WebTransportCarrierFactory struct {
	parentSet           *CarrierSet
	mu                  sync.Mutex
	c                   WebTransportFactoryConfig
	document            *protocolv4.Document
	routeBinding        protocolv4.CarrierRouteBinding
	policy              tlspolicy.Policy
	host                string
	endpoint            string
	reservation, shared resourcev4.Reference
	environment         resourcev4.Reference
	providerCharge      resourcev4.Vector
	slots               []webTransportFactorySlot
	serial              uint64
	closed, cleaned     bool
	done                chan struct{}
}

type webTransportFactorySlot = carrierFactorySlot

const webTransportFactoryRouteBytes = 16384
const webTransportFactoryRouteNodes = 1024

func WebTransportCarrierFactoryCharge(c WebTransportFactoryConfig) (resourcev4.Vector, error) {
	if len(c.RelayAccounts) > resourcev4.MaxAccountsPerCharge || !c.Relay && len(c.RelayAccounts) != 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if c.Root == nil || c.Clock == nil || len(c.Route) == 0 || len(c.Route) > webTransportFactoryRouteBytes ||
		!c.RemoteAddress.IsValid() || c.RemoteAddress.Port() == 0 || c.RemoteAddress.Addr().Zone() != "" ||
		c.Connections == 0 || c.Connections > 1024 || c.RuntimeBytes == 0 || len(c.Origin) > 1024 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := webtransport.OwnedCharge(c.Options); err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(webTransportFactoryRouteBytes, webTransportFactoryRouteNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	perSlot := uint64(unsafe.Sizeof(webTransportFactorySlot{})) + uint64(unsafe.Sizeof(factoryWebTransport{})) + uint64(unsafe.Sizeof(factoryPreparation{})) + native.EnvironmentBorrowBytes() + tlspolicy.BackingBytes() + 4096
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(WebTransportCarrierFactory{})) + uint64(len(c.RelayAccounts))*uint64(unsafe.Sizeof(resourcev4.Account{})) + decoder + 4096 + uint64(c.Connections)*perSlot,
		resourcev4.Items: 3*uint64(c.Connections) + 1, resourcev4.WorkSlots: uint64(c.Connections),
		resourcev4.Tasks: uint64(c.Connections), resourcev4.Timers: uint64(c.Connections)}).
		Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewWebTransportCarrierFactory(c WebTransportFactoryConfig, reservation, environment resourcev4.Reference) (_ *WebTransportCarrierFactory, err error) {
	charge, err := WebTransportCarrierFactoryCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckRoot(c.Root); err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	c.RelayAccounts = append([]resourcev4.Account(nil), c.RelayAccounts...)
	factory := &WebTransportCarrierFactory{c: c, reservation: owned, environment: environment, done: make(chan struct{})}
	defer func() {
		if err != nil {
			factory.Close()
		}
	}()
	factory.shared, err = environment.Borrow()
	if err != nil {
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(webTransportFactoryRouteBytes, webTransportFactoryRouteNodes)
	if err != nil {
		return nil, err
	}
	factory.document, err = decoder.DecodeMap(c.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	leg, binding, err := factory.document.BindCarrierRoute(c.Role, c.Relay, false, 2, c.Deployment)
	if err != nil {
		return nil, err
	}
	factory.routeBinding = binding
	pathKind, _ := factory.document.Root().Named("Route", "path_kind").Uint()
	host, _ := leg.Named("Leg", "host").Text()
	port, _ := leg.Named("Leg", "port").Uint()
	alpn, _ := leg.Named("Leg", "alpn").Text()
	legPath, _ := leg.Named("Leg", "path").Text()
	subprotocol, _ := leg.Named("Leg", "subprotocol").Text()
	wantPath := webtransport.PathDirect
	if pathKind == 1 {
		wantPath = webtransport.PathTunnel
	}
	if host == "" || port != uint64(c.RemoteAddress.Port()) || alpn != "h3" ||
		legPath != wantPath || subprotocol != "" || !protocolv4.LegAllowsOrigin(leg, c.Origin, c.Origin != "") {
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && address != c.RemoteAddress.Addr() {
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	factory.policy, err = tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
	if err != nil {
		return nil, err
	}
	if factory.policy.RequiresRoots() && c.Roots == nil || !factory.policy.RequiresRoots() && c.Roots != nil {
		return nil, resourcev4.ErrConfiguration
	}
	factory.host = host
	factory.endpoint = "https://" + net.JoinHostPort(host, strconv.Itoa(int(port))) + legPath
	factory.c.Origin = strings.Clone(c.Origin)
	factory.c.Route = nil
	if c.Roots != nil {
		factory.c.Roots = c.Roots.Clone()
	}
	factory.providerCharge, err = webtransport.OwnedCharge(c.Options)
	if err != nil {
		return nil, err
	}
	factory.slots = make([]webTransportFactorySlot, c.Connections)
	return factory, nil
}

func (factory *WebTransportCarrierFactory) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	return factory.prepareCarrier(ctx, request, nil)
}

func (factory *WebTransportCarrierFactory) prepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest, preparation *factoryPreparation) (_ *sessionv4.PreparedCarrier, err error) {
	if factory == nil || ctx == nil || request.Config.Deadline == nil || request.Config.Role != factory.c.Role ||
		request.Budget.PreauthBytes == 0 || request.Budget.PreauthBytes > 262144 ||
		request.Budget.WorkUnits == 0 || request.Budget.WorkUnits > math.MaxInt64 ||
		!request.Config.Deadline.BelongsTo(factory.c.Clock) || !request.Config.Session.Contract.Valid() ||
		request.Config.Session.ArtifactDigest == ([32]byte{}) || request.Config.Attempt == ([16]byte{}) ||
		request.Config.Candidate.Index >= 16 || request.Config.Candidate.CandidateID == ([16]byte{}) ||
		request.Config.Candidate.RouteDigest == ([32]byte{}) || request.Config.Reservation == request.Config.Environment {
		return nil, resourcev4.ErrConfiguration
	}
	switch request.Config.Session.Contract.Limits().ApplicationProfile {
	case "transport", "services", "execution":
	default:
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
	// Registry availability is a prerequisite, never inferred from WebTransport API
	// support. The original complete Session graph must still qualify its tuple.
	if _, ok := protocolv4.ConnectionAssurance("native_webtransport_tls13"); !ok {
		return nil, protocolv4.ErrRequiredGuaranteeUnavailable
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
	prepareCtx, cancelCause := newCarrierPreparationContext(ctx)
	cancel := func() { cancelCause(context.Canceled) }
	defer cancel()
	factory.mu.Lock()
	closed := factory.closed
	factory.slots[slot].cancel = cancel
	factory.mu.Unlock()
	if closed {
		return nil, resourcev4.ErrClosed
	}
	// One admitted timer/task observes the original trusted deadline through
	// actual dial/open return. The task is joined before this slot can retire.
	stop, stopped := make(chan struct{}), make(chan struct{})
	deadline := request.Config.Deadline
	go watchCarrierPreparation(ctx, prepareCtx, cancelCause, deadline, stop, stopped)
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
	copy(identity[32:48], "wt-provider-v4/")
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
	defer reservation.Release()
	now, err := factory.c.Clock.Sample()
	if err != nil {
		return nil, err
	}
	policy, err := factory.policy.Prepare(now.Interval)
	if err != nil {
		return nil, err
	}
	provider := &factoryWebTransport{factory: factory, slot: slot, serial: serial}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"}, ServerName: factory.host, InsecureSkipVerify: true, SessionTicketsDisabled: true}
	// The mandatory verifier performs either CA+logical target verification or
	// exact active signed DER pin verification over the whole trusted interval.
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if err := deadline.Check(); err != nil {
			return err
		}
		if state.NegotiatedProtocol != "h3" || state.DidResume {
			return webtransport.ErrInvalidTLS
		}
		sample, err := factory.c.Clock.Sample()
		if err != nil {
			return err
		}
		provider.verification, err = policy.Verify(state, factory.host, factory.c.Roots, sample.Interval)
		return err
	}
	defer func() {
		if !transferred && provider.connection != nil {
			_ = provider.Close()
			_ = provider.WaitCleanup(context.Background())
			// Slot ownership still belongs to this Prepare call on failure.
			_ = provider.retireNative()
		}
	}()
	err = RunNativeDial(prepareCtx, factory.c.DialScope, func() error {
		provider.connection, err = webtransport.DialOwned(prepareCtx, factory.c.RemoteAddress, factory.endpoint, factory.c.Origin, tlsConfig, factory.c.Options,
			request.Budget.PreauthBytes, request.Budget.WorkUnits, reservation, request.Config.Environment, providerEnvironment)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err = provider.CheckEnvironment(request.Config.Environment); err != nil {
		return nil, err
	}
	if err = request.Config.Deadline.Check(); err != nil {
		return nil, err
	}
	provider.maintenance, err = provider.connection.OpenMaintenance(prepareCtx)
	if err != nil {
		return nil, err
	}
	if _, err = provider.ConnectionGuarantees(); err != nil {
		return nil, err
	}
	prepare := sessionv4.NewPreparedStream
	if factory.c.Relay {
		prepare = sessionv4.NewPreparedRelayStream
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

func (factory *WebTransportCarrierFactory) release(index int, serial uint64) {
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

func (factory *WebTransportCarrierFactory) cleanupLocked() {
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
	factory.c.Roots, factory.c.Route, factory.slots = nil, nil, nil
	factory.shared.Release()
	factory.reservation.Release()
	close(factory.done)
}

func (factory *WebTransportCarrierFactory) Close() {
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

func (factory *WebTransportCarrierFactory) WaitCleanup(ctx context.Context) error {
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

// factoryWebTransport exposes only the original maintenance I/O and concrete native
// connection to trusted Session assembly. Closing maintenance closes the whole
// carrier; native application streams keep their original retirement owners.
type factoryWebTransport struct {
	factory            *WebTransportCarrierFactory
	slot               int
	serial             uint64
	connection         *webtransport.OwnedConnection
	maintenance        *webtransport.OwnedStream
	verification       tlspolicy.Verification
	closeOnce          sync.Once
	closeErr           error
	retireMu           sync.Mutex
	maintenanceRetired bool
	retired            bool
	slotReleased       bool
}

func (provider *factoryWebTransport) NativeConnection() *webtransport.OwnedConnection {
	return provider.connection
}

func (provider *factoryWebTransport) Read(dst []byte) (int, error) {
	return provider.maintenance.Read(dst)
}

func (provider *factoryWebTransport) Write(src []byte) (int, error) {
	return provider.maintenance.Write(src)
}

func (provider *factoryWebTransport) CheckEnvironment(environment resourcev4.Reference) error {
	return provider.connection.CheckEnvironment(environment)
}

func (provider *factoryWebTransport) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	state, err := provider.connection.TLSState()
	if err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	if state.NegotiatedProtocol != "h3" {
		return protocolv4.V4ConnectionGuarantees{}, webtransport.ErrInvalidTLS
	}
	now, err := provider.factory.c.Clock.Sample()
	if err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	if err = provider.verification.Check(now.Interval); err != nil {
		return protocolv4.V4ConnectionGuarantees{}, err
	}
	guarantees, ok := protocolv4.ConnectionAssurance("native_webtransport_tls13")
	if !ok || !guarantees.Valid() {
		return protocolv4.V4ConnectionGuarantees{}, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	return provider.factory.routeBinding.Check(guarantees)
}

func (provider *factoryWebTransport) Close() error {
	provider.closeOnce.Do(func() {
		var streamErr error
		if provider.maintenance != nil {
			streamErr = provider.maintenance.Close()
		}
		provider.closeErr = errors.Join(streamErr, provider.connection.Close())
	})
	return provider.closeErr
}

func (provider *factoryWebTransport) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	provider.retireMu.Lock()
	defer provider.retireMu.Unlock()
	if provider.retired {
		return nil
	}
	if provider.maintenance != nil && !provider.maintenanceRetired {
		if err := provider.maintenance.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	return provider.connection.WaitCleanup(ctx)
}

func (provider *factoryWebTransport) retireNative() error {
	provider.retireMu.Lock()
	defer provider.retireMu.Unlock()
	if provider.retired {
		return nil
	}
	if provider.maintenance != nil && !provider.maintenanceRetired {
		if err := provider.maintenance.Retire(); err != nil {
			return err
		}
		provider.maintenanceRetired = true
	}
	if err := provider.connection.Retire(); err != nil {
		return err
	}
	provider.retired = true
	return nil
}

func (provider *factoryWebTransport) Retire() error {
	if err := provider.retireNative(); err != nil {
		return err
	}
	// Serialize the one factory-slot release with concurrent retirement calls.
	provider.retireMu.Lock()
	defer provider.retireMu.Unlock()
	if !provider.slotReleased {
		provider.factory.release(provider.slot, provider.serial)
		provider.slotReleased = true
	}
	return nil
}

var _ sessionv4.ConsumerCarrierFactory = (*WebTransportCarrierFactory)(nil)
var _ io.ReadWriteCloser = (*factoryWebTransport)(nil)

// A single fixed endpoint has one useful preparation lane per Connect. Other
// Sessions retain their independent slots from the same finite factory table.
func (factory *WebTransportCarrierFactory) PreparationParallelism() uint8 {
	if factory == nil {
		return 0
	}
	return 1
}

func (factory *WebTransportCarrierFactory) AdmitPreparation(request sessionv4.CarrierPreparationAdmissionRequest) (sessionv4.CarrierPreparation, error) {
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

func (factory *WebTransportCarrierFactory) checkPreparation(index int, serial uint64) error {
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

func (factory *WebTransportCarrierFactory) closePreparation(index int, serial uint64) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if slot, err := originalFactorySlot(factory.slots, index, serial); err == nil {
		slot.closeAdmission()
	}
	factory.cleanupLocked()
}

var _ sessionv4.AdmittingConsumerCarrierFactory = (*WebTransportCarrierFactory)(nil)

// The fixed endpoint has exactly one useful candidate position per source.
func (factory *WebTransportCarrierFactory) AdmitPreparations(request sessionv4.CarrierPreparationAdmissionRequest, output []sessionv4.CarrierPreparation) error {
	if len(output) != 1 || output[0] != nil {
		return resourcev4.ErrConfiguration
	}
	preparation, err := factory.AdmitPreparation(request)
	output[0] = preparation
	return err
}

func (factory *WebTransportCarrierFactory) attachSet(set *CarrierSet) { factory.parentSet = set }

func (factory *WebTransportCarrierFactory) setView() carrierSetFactory {
	return carrierSetFactory{owner: factory, mu: &factory.mu, document: &factory.document, closed: &factory.closed, slots: &factory.slots, serial: &factory.serial, reservation: factory.reservation, environment: factory.environment, clock: factory.c.Clock}
}
