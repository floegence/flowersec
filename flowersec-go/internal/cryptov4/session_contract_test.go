package cryptov4

import (
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"testing"
	"time"
)

// testSessionContract is an explicit synthetic contract for record/handshake
// tests. Original signed Artifact binding is exercised by negotiation tests.
func testSessionContract(t *testing.T, profile, application string, frame, streams uint32, idle, expires uint64) protocolv4.ArtifactSessionParameters {
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
	fields := []protocolv4.Field{
		{Name: "max_frame", Number: uint64(frame)}, {Name: "max_streams", Number: uint64(streams)},
		{Name: "max_credit", Number: 65536}, {Name: "idle_duration_ms", Number: idle},
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

func TestRecordEngineSignedAndZeroScopeLimits(t *testing.T) {
	clock := cryptoClock(t, time.Now)
	born, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	maximum, err := protocolv4.SessionMaxStreams()
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
			config := Config{Authorization: testAuthorization{}, Profile: profile, ApplicationProfile: "transport", Root: [32]byte{1}, HandshakeHash: [32]byte{2}, SendDirection: role, MaxFrame: 4096, MaxScopes: 0, SignedMaxScopes: 0, PendingScopes: 2, WorkSlots: 2, RootBorn: born, AuthorizationDeadlineMS: born.LowerMS + 3600000, Clock: clock, Maintenance: MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
			engine, err := NewEngine(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.Activate(); err != nil {
				t.Fatal(err)
			}
			if err := engine.OpenScope(1); !errors.Is(err, ErrCapacity) {
				t.Fatal("zero capacity opened scope", err)
			}
			packet, err := engine.Seal(protocolv4.FramePing, 0, []byte{1})
			if err != nil {
				t.Fatal("zero capacity disabled maintenance", err)
			}
			packet.Release()
			engine.Close()
			for _, change := range []func(*Config){
				func(c *Config) { c.MaxScopes = 1 },
				func(c *Config) { c.SignedMaxScopes = maximum + 1 },
				func(c *Config) { c.ApplicationProfile = "services" },
				func(c *Config) { c.ApplicationProfile = "execution" },
			} {
				bad := config
				change(&bad)
				if e, err := NewEngine(bad); e != nil || !errors.Is(err, ErrConfiguration) {
					t.Fatal("invalid signed/local capacity", err)
				}
			}
		}
	}
}

func TestHandshakeRecordPreparationPreservesFullSignedFrame(t *testing.T) {
	client, server := handshakePair(t, protocolv4.DHProfileX25519)
	c, _ := completeNoise(t, client, server)
	for _, change := range []func(*Config){
		func(c *Config) { c.MaxFrame-- },
		func(c *Config) { c.MaxFrame++ },
		func(c *Config) { c.MaxScopes++ },
	} {
		bad := initialRecordConfig()
		change(&bad)
		if e, err := c.PrepareRecords(bad); e != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("contract override accepted", err)
		}
	}
	config := initialRecordConfig()
	config.MaxScopes = 0
	e, err := c.PrepareRecords(config)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	local, pending, _ := e.ScopeLimits()
	if local != 0 || pending != 2 || e.SignedScopeLimit() != 4 || e.MaxFrame() != 4096 || e.SessionParameters() != c.config.Session {
		t.Fatal("signed/local envelope changed")
	}
}
