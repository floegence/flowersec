package sessionv4

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Existing owner-union tests inspect the production geometry's expanded values.
// Production callers retain only the compact geometry.
func sessionCoreCharges(c SessionCoreConfig) (charges [coreOwnerCapacity]resourcev4.Vector, total resourcev4.Vector, count uint32, err error) {
	geometry, err := sessionCoreChargeGeometry(c)
	for position := range charges {
		charges[position] = geometry.charge(position)
	}
	return charges, geometry.total, geometry.owners, err
}

// This independently expanded accounting oracle preserves every original owner
// and the order of checked additions. It is deliberately confined to tests.
func expandedSessionCoreCharges(c SessionCoreConfig) (charges [coreOwnerCapacity]resourcev4.Vector, total resourcev4.Vector, count uint32, err error) {
	if c.MixedCarrier {
		if c.Native == c.MessageCarrier {
			return charges, total, count, cryptov4.ErrConfiguration
		}
		native, shared := coreCarrierMode(c, false), coreCarrierMode(c, true)
		native.MixedCarrier, shared.MixedCarrier = false, false
		// Shared carriers negotiate no datagrams. Keep the captured capability on
		// the mixed configuration so later selection preserves the same union.
		shared.Datagrams = false
		nc, _, _, e := expandedSessionCoreCharges(native)
		if e != nil {
			return charges, total, count, e
		}
		sc, _, _, e := expandedSessionCoreCharges(shared)
		if e != nil {
			return charges, total, count, e
		}
		for owner := range charges {
			for dimension := range charges[owner] {
				charges[owner][dimension] = max(nc[owner][dimension], sc[owner][dimension])
			}
			if charges[owner] != (resourcev4.Vector{}) {
				total, e = total.Add(charges[owner])
				if e != nil {
					return charges, total, count, e
				}
				count++
			}
		}
		return charges, total, count, nil
	}
	if c.Handlers != (SessionStreamHandlerConfig{}) {
		if c.Handlers.Plan != nil && c.Streams == (SessionStreamConfig{}) || uint64(c.Handlers.Concurrency) > uint64(c.Open.Opening)+uint64(c.Open.IngressItems) {
			err = cryptov4.ErrConfiguration
			return
		}
		charges[coreHandlersOwner], err = sessionStreamDispatcherCharge(c.Handlers)
		if err != nil {
			return
		}
	}
	signed := c.Session.Contract.Limits()
	profileSupported := signed.ApplicationProfile == "transport" && !c.applicationServices || c.applicationServices && (signed.ApplicationProfile == "services" || signed.ApplicationProfile == "execution")
	if !c.Session.Contract.Valid() || !profileSupported || c.Session.SessionNotAfterMS <= c.Session.IssuedAtMS || c.Native && c.MessageCarrier ||
		c.RuntimeBytes == 0 || c.DecoderNodes <= 0 || c.MaxDataPayloadBytes == 0 || c.MaxDataPayloadBytes > uint64(signed.MaxFrame) ||
		c.Open.Active > c.MaxScopes || c.Open.IngressItems > c.PendingScopes || c.ProbeSlots == 0 || c.ProbeSlots > 8 || c.PongSlots == 0 || c.PongSlots > c.Messages.IngressBurst ||
		c.DispatchTimeoutMS == 0 || c.RetirementTimeoutMS == 0 || (c.Automatic != (AutomaticLivenessPolicy{}) && (c.Automatic.IntervalMS == 0 || c.Automatic.SubmissionMS == 0 || c.Automatic.ResponseMS == 0 || c.Automatic.MissThreshold == 0 || c.Automatic.SubmissionMS > math.MaxUint64-c.Automatic.ResponseMS)) ||
		c.Messages.IngressRefillMS == 0 || c.Messages.ReplyTimeoutMS == 0 || c.Termination.NormalMS == 0 || c.Termination.QuarantineMS == 0 || c.Termination.NormalMS > math.MaxUint64-c.Termination.QuarantineMS || c.Termination.QuarantineDirections == 0 || c.Termination.QuarantineDirections > 32 || c.Termination.QuarantineMS > 10000 ||
		c.Rekey.LocalPrepareMS == 0 || c.Rekey.ProtocolPrepareMS == 0 || c.Rekey.ConfirmationMS == 0 {
		err = cryptov4.ErrConfiguration
		return
	}
	var send uint64
	for class, workers := range c.SendWorkers {
		if (c.Open.PerClass[class] == 0) != (workers == 0) {
			err = cryptov4.ErrConfiguration
			return
		}
		send += uint64(workers)
	}
	if c.Open.Active == 0 && (send != 0 || c.NativeAuthWorkers != 0) || c.Open.Active != 0 && send == 0 || send > uint64(c.Open.Active) {
		err = cryptov4.ErrConfiguration
		return
	}
	if c.Native {
		// DATA publication transfers to charged per-Stream output. Fixed
		// authentication workers and one send/key lane cover crypto work;
		// every actual provider worker remains separately admitted below.
		cryptoSend := send
		if c.Streams != (SessionStreamConfig{}) {
			cryptoSend = min(send, 1)
		}
		if c.Datagrams {
			cryptoSend += 2
		}
		if c.NativeIngress.FrameTimeoutMS == 0 || c.NativeIngress.RefillMS == 0 || c.NativeIngress.Burst == 0 || c.Open.Active != 0 && (c.NativeAuthWorkers == 0 || c.NativeAuthWorkers > 128) || cryptoSend+uint64(c.NativeAuthWorkers) > uint64(c.WorkSlots) {
			err = cryptov4.ErrConfiguration
			return
		}
	} else if c.NativeAuthWorkers != 0 || c.SharedDiscard.MaxRecords == 0 || c.SharedDiscard.MaxBytes == 0 || c.SharedDiscard.DurationMS == 0 || send+1 > uint64(c.WorkSlots) {
		err = cryptov4.ErrConfiguration
		return
	}
	maxInt := uint64(^uint(0) >> 1)
	if c.Datagrams {
		if !c.Native || c.Streams == (SessionStreamConfig{}) || uint64(c.WorkSlots) < uint64(c.NativeAuthWorkers)+3 {
			err = cryptov4.ErrConfiguration
			return
		}
		charges[coreUnreliableOwner], err = unreliableCharge(c)
		if err != nil {
			return
		}
	}
	if uint64(c.PongSlots) > maxInt/uint64(unsafe.Sizeof(PongSlot{})) || uint64(c.RekeyWaitSlots) > maxInt/uint64(unsafe.Sizeof(RekeyWaitSlot{})) {
		err = cryptov4.ErrConfiguration
		return
	}
	usage, e := coreUsageRegistry()
	if e != nil {
		err = e
		return
	}
	key, ok := usage[c.Session.Profile]
	if !ok || c.Maintenance.Calls == 0 || c.Maintenance.Blocks == 0 || c.Maintenance.Bytes == 0 || c.Maintenance.Calls >= min(key.Key.Seal, key.Key.Open) || c.Maintenance.Blocks >= key.Key.Blocks || c.Maintenance.Bytes >= key.Key.Bytes {
		err = cryptov4.ErrConfiguration
		return
	}
	if err = c.validateTime(); err != nil {
		return
	}
	if c.Streams != (SessionStreamConfig{}) {
		if c.Open.Active == 0 || c.Streams.InitialReceiveLimit > signed.MaxCredit {
			err = cryptov4.ErrConfiguration
			return
		}
		if _, err = sessionStreamCharges(c.Streams, c.Session.Profile, uint64(signed.MaxFrame), c.MaxDataPayloadBytes, 0); err != nil {
			return
		}
		if c.Native {
			// Every admitted native send direction has an independent worker.
			// A blocked physical Write cannot occupy a healthy Stream's only
			// service position in the same class.
			for class, active := range c.Open.PerClass {
				if c.SendWorkers[class] < active {
					err = cryptov4.ErrConfiguration
					return
				}
			}
			charges[coreNativeStreamsOwner], err = nativeStreamTransportCharge(c)
			if err != nil {
				return
			}
			for i := uint32(0); i < c.Open.IngressItems; i++ {
				charges[coreNativeOpenReceiverStart+int(i)], err = RecordReceiverCharge(signed.MaxFrame, c.DecoderNodes, c.decode())
				if err != nil {
					return
				}
			}
		}
		charges[coreReceivePoolOwner], err = ReceivePoolCharge(c.Streams.ReceivePoolBytes, c.Open.Active)
		if err != nil {
			return
		}
	}
	// ProbeSlot and PongSlot arrays are already included in their service
	// charges. The remaining original rekey causes/credit and writer belong here.
	metadata := uint64(unsafe.Sizeof(SessionCorePlan{})) + uint64(unsafe.Sizeof(RecordWriter{})) + uint64(unsafe.Sizeof(RekeyCredit{})) + uint64(unsafe.Sizeof(RekeyCauses{})) + uint64(unsafe.Sizeof(RekeyIntent{})) + uint64(unsafe.Sizeof(RekeyCharge{})) + 2*uint64(unsafe.Sizeof(rekeyTiming{})) + 4*uint64(unsafe.Sizeof(timev4.Deadline{})) + 2*uint64(unsafe.Sizeof(timev4.Window{}))
	// Each manual waiter can retain a different completed intent across later
	// rounds. Those original identities and security caps outlive current intent.
	metadata += uint64(c.RekeyWaitSlots) * (uint64(unsafe.Sizeof(RekeyWaitSlot{})) + uint64(unsafe.Sizeof(RekeyIntent{})) + uint64(unsafe.Sizeof(timev4.Deadline{})))
	charges[corePlanOwner], err = (resourcev4.Vector{resourcev4.SDKBytes: metadata, resourcev4.Items: 16 + 3*uint64(c.RekeyWaitSlots), resourcev4.Sessions: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return
	}
	charges[coreEngineOwner], err = cryptov4.EngineCharge(c.records(0), c.EngineResources)
	if err != nil {
		return
	}
	charges[coreOpenOwner], err = OpenAdmissionCharge(c.Open)
	if err != nil {
		return
	}
	charges[coreLivenessOwner], err = LivenessCharge(int(c.ProbeSlots), c.Automatic != (AutomaticLivenessPolicy{}))
	if err != nil {
		return
	}
	charges[coreMessagesOwner], err = MaintenanceMessagesCharge(int(c.PongSlots))
	if err != nil {
		return
	}
	charges[coreTerminationOwner], err = StreamTerminationServiceCharge(c.Open.Active)
	if err != nil {
		return
	}
	barriers, e := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if e != nil {
		err = e
		return
	}
	charges[coreRekeyOwner] = RekeyServiceCharge(signed.MaxFrame, min(signed.MaxStreams, uint32(barriers)))
	charges[coreRetirementOwner], err = RetirementServiceCharge()
	if err != nil {
		return
	}
	charges[coreRuntimeOwner] = SessionRuntimeCharge()
	charges[coreLifecycleOwner] = SessionLifecycleCharge()
	if c.MessageCarrier {
		charges[coreCarrierOwner], err = SessionMessageInputCharge(c.messageOptions())
	} else {
		charges[coreCarrierOwner], err = sessionStreamInputCharge(c.WorkSlots + 2)
	}
	if err != nil {
		return
	}
	if c.Open.Active != 0 {
		charges[coreSendOwner], err = SendServiceCharge(c.Open.Active, c.SendWorkers)
		if err != nil {
			return
		}
	}
	decode := c.decode()
	if c.Native {
		charges[coreIngressOwner], err = MaintenanceIngressCharge(signed.MaxFrame)
		if err != nil {
			return
		}
		charges[coreIngressReceiverOwner], err = RecordReceiverCharge(signed.MaxFrame, c.DecoderNodes, decode)
		if err != nil {
			return
		}
		if c.Open.Active != 0 {
			charges[coreNativeAuthOwner], err = NativeAuthServiceCharge(c.Open.Active, c.NativeAuthWorkers)
			if err != nil {
				return
			}
			for i := uint32(0); i < c.NativeAuthWorkers; i++ {
				charges[coreNativeReceiverStart+int(i)] = charges[coreIngressReceiverOwner]
			}
		}
	} else {
		charges[coreIngressOwner], err = SharedIngressCharge(signed.MaxFrame, c.DecoderNodes, decode)
		if err != nil {
			return
		}
	}
	serviceSlots, e := appendExpandedStreamServiceFloorCharges(c, &charges)
	if e != nil {
		err = e
		return
	}
	charges[corePlanOwner], err = charges[corePlanOwner].Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(serviceSlots) * uint64(unsafe.Sizeof(streamServiceFloor{})), resourcev4.Items: uint64(serviceSlots)})
	if err != nil {
		return
	}
	for _, charge := range charges {
		if charge != (resourcev4.Vector{}) {
			total, err = total.Add(charge)
			if err != nil {
				return
			}
			count++
		}
	}
	return
}

func appendExpandedStreamServiceFloorCharges(c SessionCoreConfig, charges *[coreOwnerCapacity]resourcev4.Vector) (uint32, error) {
	count, vectors, err := streamServiceFloorCharges(c)
	if err != nil {
		return 0, err
	}
	for slot := 0; slot < int(count); slot++ {
		for i, vector := range vectors {
			if vector == (resourcev4.Vector{}) {
				continue
			}
			charges[coreStreamServiceStart+slot*streamServiceOwners+i], err = resourcev4.ProtectedCharge(vector)
			if err != nil {
				return 0, err
			}
		}
	}
	return count, nil
}

// Geometry-only registrations exercise the full provider envelope without
// constructing or borrowing executable handlers, roots, or provider resources.
func sessionCoreGeometryServiceConfig(t *testing.T, mode string, target uint32) SessionCoreConfig {
	t.Helper()
	c := corePlanUnitConfig(t, true)
	c.Session = testSessionContract(t, c.Session.Profile, "transport", 4096, 128, 0, c.Session.SessionNotAfterMS, 1<<20)
	c.MaxScopes, c.PendingScopes, c.WorkSlots = 128, 128, 128
	c.Open = OpenLimits{Active: 128, Opening: 128, Terminal: 256, RejectionReserve: 128, IngressItems: 128, IngressBytes: 512 << 10,
		PerClass: [3]uint32{128}, PerOpener: [2][3]uint32{{128}, {128}}, Lifetime: [2][3]uint64{{1024}, {1024}}}
	c.NativeAuthWorkers = 127
	c.Streams = factoryStreamConfig()
	c.Streams.ReceivePoolBytes = 128 * c.Streams.ReceiveBytes
	c.MessageRuntimeBytes = 8192
	c.Handlers = SessionStreamHandlerConfig{Concurrency: 2, TimeoutMS: 1000, ServiceTarget: target, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 16384,
		Plan: &StreamHandlerPlan{executor: &ApplicationExecutor{config: ApplicationExecutorConfig{RuntimeBytesPerTask: 16384}},
			registrations: []streamHandlerRegistration{
				{config: RawStreamHandlerConfig{Kind: "geometry/raw", Slots: 128, Delegated: &DelegatedStreamService{Options: delegatedRawOptions()}}},
				{config: RawStreamHandlerConfig{Kind: "geometry/http", Slots: 32, HTTP: &DelegatedHTTPService{Options: delegatedHTTPOptions()}}},
				{config: RawStreamHandlerConfig{Kind: "geometry/controlled", Slots: 8, ControlledHTTP: &ControlledHTTPService{Options: delegatedHTTPOptions()}}},
			}}}
	switch mode {
	case "shared-stream":
		c.Native, c.NativeAuthWorkers, c.SendWorkers = false, 0, [3]uint32{1}
	case "shared-messages":
		c = coreCarrierMode(c, true)
	case "native":
		c = coreCarrierMode(c, false)
	case "native-datagrams":
		c = coreCarrierMode(c, false)
		c.NativeAuthWorkers, c.Datagrams = 125, true
	case "mixed-native":
		c = coreCarrierMode(c, false)
		c.MixedCarrier = true
	case "mixed-messages":
		c = coreCarrierMode(c, true)
		c.MixedCarrier = true
	case "mixed-datagrams":
		c = coreCarrierMode(c, true)
		c.NativeAuthWorkers, c.Datagrams, c.MixedCarrier = 125, true, true
	default:
		t.Fatal("unknown geometry mode", mode)
	}
	return c
}

func assertSessionCoreGeometryMatchesExpanded(t *testing.T, c SessionCoreConfig) sessionCoreGeometry {
	t.Helper()
	want, wantTotal, wantOwners, err := expandedSessionCoreCharges(c)
	if err != nil {
		t.Fatal("expanded reference rejected valid fixture", err)
	}
	got, err := sessionCoreChargeGeometry(c)
	if err != nil {
		t.Fatal("compact geometry rejected valid fixture", err)
	}
	wantReferences := wantOwners + 2
	if c.MessageCarrier || c.MixedCarrier {
		wantReferences++
	}
	for position, charge := range want {
		if got.charge(position) != charge {
			t.Fatalf("owner %d charge = %v, want %v", position, got.charge(position), charge)
		}
		if position >= coreStreamServiceStart && charge != (resourcev4.Vector{}) {
			component := (position - coreStreamServiceStart) % streamServiceOwners
			wantReferences += uint32(streamServiceBorrows(component))
			if component == streamFactoryMetadata {
				wantReferences++
			}
		}
	}
	if got.total != wantTotal || got.owners != wantOwners || got.references != wantReferences {
		t.Fatalf("compact total/owners/references = %v/%d/%d, want %v/%d/%d", got.total, got.owners, got.references, wantTotal, wantOwners, wantReferences)
	}
	total, owners, err := SessionCoreRequirements(c)
	if err != nil || total != wantTotal || owners != wantOwners {
		t.Fatal("public requirements diverged", total, owners, err)
	}
	references, err := SessionCoreReferenceSlots(c)
	if err != nil || references != wantReferences {
		t.Fatal("public reference capacity diverged", references, err)
	}
	for _, position := range []int{-1, coreOwnerCapacity, coreOwnerCapacity + streamServiceOwners} {
		if got.charge(position) != (resourcev4.Vector{}) {
			t.Fatal("geometry exposed an owner outside original capacity", position)
		}
	}
	return got
}

func TestSessionCoreGeometryPreservesEveryOriginalCarrierAndServiceOwner(t *testing.T) {
	for _, mode := range []string{"shared-stream", "shared-messages", "native", "native-datagrams", "mixed-native", "mixed-messages", "mixed-datagrams"} {
		for _, target := range []uint32{1, 3, 0, 128} {
			t.Run(fmt.Sprintf("%s/floors-%d", mode, target), func(t *testing.T) {
				c := sessionCoreGeometryServiceConfig(t, mode, target)
				g := assertSessionCoreGeometryMatchesExpanded(t, c)
				wantSlots := target
				if wantSlots == 0 {
					wantSlots = 64
				}
				if g.serviceSlots != wantSlots {
					t.Fatal("service envelope lost original slot count", g.serviceSlots, wantSlots)
				}
			})
		}
	}
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("no-streams/native-%t", native), func(t *testing.T) {
			g := assertSessionCoreGeometryMatchesExpanded(t, corePlanUnitConfig(t, native))
			if g.serviceSlots != 0 || g.services != ([streamServiceOwners]resourcev4.Vector{}) {
				t.Fatal("bare core retained delegated service charges")
			}
		})
	}
	c := sessionCoreGeometryServiceConfig(t, "mixed-messages", 128)
	c.Handlers.Plan.registrations = nil
	if g := assertSessionCoreGeometryMatchesExpanded(t, c); g.serviceSlots != 0 {
		t.Fatal("empty immutable registry admitted service positions")
	}
}

func TestSessionCoreGeometryPreservesRejectionAndOverflow(t *testing.T) {
	for _, failure := range []string{"shared-decoder", "runtime-overflow", "floor-overflow", "floor-total-overflow", "floor-receive", "floor-credit", "floor-target", "closed-plan", "ambiguous-carrier"} {
		t.Run(failure, func(t *testing.T) {
			c := sessionCoreGeometryServiceConfig(t, "mixed-native", 3)
			switch failure {
			case "shared-decoder":
				c.MessageRuntimeBytes = 0
			case "runtime-overflow":
				c.RuntimeBytes = math.MaxUint64
			case "floor-overflow":
				c.Handlers.Plan.registrations[0].config.Delegated.Options.RuntimeBytes = math.MaxUint64
			case "floor-total-overflow":
				c.Handlers.Plan.registrations[0].config.Delegated.Options.ExternalRuntime[resourcev4.ProviderBytes] = math.MaxUint64 / 2
			case "floor-receive":
				c.Streams.ReceivePoolBytes = c.Streams.ReceiveBytes
			case "floor-credit":
				c.Session = testSessionContract(t, c.Session.Profile, "transport", 4096, 128, 0, c.Session.SessionNotAfterMS, 64)
			case "floor-target":
				c.Handlers.ServiceTarget = 129
			case "closed-plan":
				c.Handlers.Plan.closed = true
			case "ambiguous-carrier":
				c.Native, c.MessageCarrier = true, true
			}
			_, wantTotal, wantOwners, wantErr := expandedSessionCoreCharges(c)
			got, gotErr := sessionCoreChargeGeometry(c)
			if wantErr == nil || !errors.Is(gotErr, wantErr) {
				t.Fatal("compact geometry changed configuration rejection", gotErr, wantErr)
			}
			if got.total != wantTotal || got.owners != wantOwners {
				t.Fatal("failed geometry changed checked accounting result", got.total, got.owners, wantTotal, wantOwners)
			}
			if references, err := SessionCoreReferenceSlots(c); references != 0 || !errors.Is(err, wantErr) {
				t.Fatal("failed geometry exposed reference capacity", references, err)
			}
		})
	}
}

func TestSessionCoreGeometryFrozenRequestsKeepOriginalOwnerNumbers(t *testing.T) {
	c, root, environment, owner, scope := serviceFloorFixture(t, "")
	want, _, wantOwners, err := expandedSessionCoreCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot()
	var batch sessionCoreBatch
	if err := describeSessionCoreBatch(&batch, c, root, owner, environment, scope); err != nil {
		t.Fatal(err)
	}
	defer batch.release()
	if root.Snapshot() != before {
		t.Fatal("describing geometry borrowed or admitted resources")
	}
	// The accepted batch must keep its frozen envelope even if the caller's
	// subsequent configuration or descriptor changes before reservation.
	c.RuntimeBytes, c.Streams.ReceivePoolBytes = 1, 1
	c.Handlers.Plan.registrations[0].config.Delegated.Options.ExternalRuntime[resourcev4.ProviderBytes]++
	count := 0
	for position, charge := range want {
		if charge == (resourcev4.Vector{}) {
			continue
		}
		request, err := batch.request(count)
		if err != nil || batch.positions[count] != position || request.Charge != charge || request.Owner != admissionResourceKey(owner, uint32(position)) {
			t.Fatal("frozen request changed original charge or owner position", position, request, err)
		}
		if len(request.Accounts) != 2 || request.Accounts[0] != scope.Tenant || request.Accounts[1] != scope.Session {
			t.Fatal("frozen request lost its authoritative account scope", position)
		}
		count++
	}
	if uint32(count) != wantOwners || count != batch.count {
		t.Fatal("frozen batch changed the number of atomic requests", count, wantOwners, batch.count)
	}
	if _, err := batch.request(count); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("batch exposed a request beyond its frozen owners", err)
	}
}
