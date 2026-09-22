package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"testing"
	"time"
)

// testSessionContract is an explicit synthetic contract for record/handshake
// tests. Original signed Artifact binding is exercised by negotiation tests.
func testSessionContract(t *testing.T, profile, application string, frame, streams uint32, idle, expires uint64, credit ...uint64) protocolv4.ArtifactSessionParameters {
	t.Helper()
	applicationValue, err := protocolv4.EnumValue("SessionContract", "application_profile", application)
	if err != nil {
		t.Fatal(err)
	}
	rekey, err := protocolv4.EncodeMap(make([]byte, 32), "RekeyEnvelope", []protocolv4.Field{
		{Name: "burst_rounds", Number: 4}, {Name: "refill_period_ms", Number: 60000}, {Name: "request_start_budget_ms", Number: 10000},
	})
	if err != nil {
		t.Fatal(err)
	}
	maxCredit := uint64(65536)
	if len(credit) != 0 {
		maxCredit = credit[0]
	}
	fields := []protocolv4.Field{
		{Name: "max_frame", Number: uint64(frame)}, {Name: "max_streams", Number: uint64(streams)},
		{Name: "max_credit", Number: maxCredit}, {Name: "idle_duration_ms", Number: idle},
		{Name: "rekey_envelope", Kind: protocolv4.EncodedMap, Bytes: rekey}, {Name: "application_profile", Number: applicationValue},
	}
	if application != "transport" {
		fields = append(fields, protocolv4.Field{Name: "rpc_max_general_outstanding", Number: 32})
	}
	wire, err := protocolv4.EncodeMap(make([]byte, 64), "SessionContract", fields)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := protocolv4.NewDecoder(64, 32)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := decoder.DecodeMap(wire, "SessionContract", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	contract, err := doc.SessionContract()
	if err != nil {
		t.Fatal(err)
	}
	return protocolv4.ArtifactSessionParameters{Contract: contract, ArtifactDigest: [32]byte{1}, Profile: profile, IssuedAtMS: 1, SessionNotAfterMS: expires}
}

func TestZeroLocalStreamsPreserveAuthenticatedRejections(t *testing.T) {
	for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
		clock := sessionTestClock(t)
		local := newOpenEndpointLimits(t, role, 0, 4, 1, 1, clock, 0, testAuthorization{})
		peer := newOpenEndpointClock(t, 1-role, 4, 2, 1, clock)
		charge, err := StreamTerminationServiceCharge(0)
		if err != nil || charge[resourcev4.Tasks] != 2 || charge[resourcev4.Timers] == 0 {
			t.Fatal("zero active removed maintenance owner", err, charge)
		}
		_, reservation := testResourceReservation(t, charge, 1)
		service, err := NewStreamTerminationService(local.admission, local.maintenance, StreamTerminationPolicy{50, 100, 8}, reservation)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			service.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := service.WaitCleanup(ctx); err != nil {
				t.Error(err)
				return
			}
			if err := service.retire(); err != nil {
				t.Error(err)
			}
		})
		var output bytes.Buffer
		if _, _, err := local.admission.OpenLocal(context.Background(), BusinessStream, "example/raw", nil, &CarrierAssociation{}, local.reservation(&output, 0), streamTestDeadline(t, local.engine)); !errors.Is(err, cryptov4.ErrCapacity) || output.Len() != 0 {
			t.Fatal("zero local capacity opened stream", err)
		}
		_, pending, _, _ := startTestOpen(t, peer, local, 0)
		if _, err := local.admission.Decide(context.Background(), pending, BusinessStream, "", StreamReservation{}, local.maintenance); err != nil {
			t.Fatal("zero local capacity lost ordinary rejection", err)
		}
		applyTestOutcome(t, local, peer)
		if usage := local.admission.Usage(); usage.Active != 0 || usage.Pending != 0 || usage.RejectionProofs != 1 {
			t.Fatal("rejection acquired positive capacity", usage)
		}
	}
}

func TestRekeyPeerEnvelopeUsesSignedCapacity(t *testing.T) {
	for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
		clock := sessionTestClock(t)
		local := newOpenEndpointLimits(t, role, 0, 8, 2, 1, clock, 0, testAuthorization{})
		peer := newOpenEndpointClock(t, 1-role, 8, 2, 1, clock)
		barriers, err := NewBarriers(local.admission)
		if err != nil {
			t.Fatal(err)
		}
		schema := "REKEY_INIT"
		if role == protocolv4.ClientToServer {
			if err := barriers.Freeze(); err != nil {
				t.Fatal(err)
			}
			if err := barriers.Published(); err != nil {
				t.Fatal(err)
			}
			schema = "REKEY_REPLY"
		}
		entries := make([]protocolv4.RecordHeader, 3)
		for i := range entries {
			entries[i] = protocolv4.RecordHeader{Scope: uint64(2*i+1) + uint64(1-role), Sequence: 1}
		}
		record := barrierRecord(t, peer, local, schema, entries)
		if err := barriers.RegisterPeer(record); err != nil {
			t.Fatal("legal peer barrier shrank to local cap", err)
		}
		record.Release()
		if barriers.peerCount != 3 || barriers.awaiting != 3 || local.admission.Usage().Active != 0 {
			t.Fatal("barrier manufactured positive streams")
		}
	}
	maximum, err := protocolv4.SessionMaxStreams()
	if err != nil {
		t.Fatal(err)
	}
	local := newOpenEndpointLimits(t, 1, 0, maximum, 2, 1, sessionTestClock(t), 0, testAuthorization{})
	barriers, err := NewBarriers(local.admission)
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := protocolv4.FieldItemLimit("REKEY_INIT", "client_barrier")
	if len(barriers.peer) != bound {
		t.Fatal("barrier used ordinal-sized allocation", len(barriers.peer))
	}
}

func TestInitialRecordOverrideRejectedBeforeNoise(t *testing.T) {
	for _, change := range []func(*cryptov4.Config){
		func(c *cryptov4.Config) { c.MaxFrame-- },
		func(c *cryptov4.Config) { c.MaxFrame++ },
		func(c *cryptov4.Config) { c.MaxScopes++ },
	} {
		pair, configs := initialTestPair(t, protocolv4.DHProfileX25519, "message")
		records := initialRecordLimits()
		change(&records)
		called := false
		engine, err := pair[0].Authenticate(configs[0], records, func(*cryptov4.Engine) error { called = true; return nil })
		if engine != nil || !errors.Is(err, cryptov4.ErrConfiguration) || called || pair[0].handshake != nil {
			t.Fatal("Noise began with invalid contract", err)
		}
	}
}

func TestRecordReceiverCannotNarrowSignedFrame(t *testing.T) {
	endpoint := newOpenEndpoint(t, 0, 2, 2, 1)
	charge, err := RecordReceiverCharge(endpoint.engine.MaxFrame()-1, 64, protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	_, ref := testResourceReservation(t, charge, 1)
	defer ref.Release()
	r, err := NewRecordReceiver(endpoint.engine, 1, endpoint.engine.MaxFrame()-1, 64, protocolv4.DecodeContext{}, ref)
	if r != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("decoder silently narrowed signed frame", err)
	}
	if err := ref.Check(); err != nil {
		t.Fatal("failed validation consumed reservation", err)
	}
}

func TestHandshakeRekeyCreditKeepsOriginalSignedEnvelope(t *testing.T) {
	client, server := newBootstrapPair(t, protocolv4.DHProfileX25519, "services")
	client.complete(t, server)
	server.complete(t, client)
	for _, e := range []*bootstrapEndpoint{client, server} {
		original := e.engine.SessionParameters()
		for _, field := range []string{"burst", "refill", "start", "issued", "expires"} {
			envelope, issued, expires := original.Contract.Limits().Rekey, original.IssuedAtMS, original.SessionNotAfterMS
			switch field {
			case "burst":
				envelope.Burst++
			case "refill":
				envelope.RefillMS++
			case "start":
				envelope.RequestStartMS++
			case "issued":
				issued++
			case "expires":
				expires--
			}
			if c, err := NewRekeyCredit(e.admission, envelope, issued, expires, e.engine.Clock()); c != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal("rekey contract replaced", field, err)
			}
		}
		if c, err := NewRekeyCredit(e.admission, original.Contract.Limits().Rekey, original.IssuedAtMS, original.SessionNotAfterMS, e.engine.Clock()); c == nil || err != nil {
			t.Fatal("original rekey envelope unavailable", err)
		}
		limits := e.admission.limits
		limits.Active, limits.Opening = 0, 0
		limits.PerClass, limits.PerOpener, limits.Protected = [3]uint32{}, [2][3]uint32{}, [2][3]uint32{}
		if a, err := NewOpenAdmission(e.engine, e.admission.direction, limits); a != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("bootstrap positive slot omitted", err)
		}
	}
}
