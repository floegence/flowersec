package assemblyv4

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	carrierws "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
	"github.com/gorilla/websocket"
)

type webSocketFactoryFixture struct {
	factory *WebSocketCarrierFactory
	request sessionv4.CarrierPreparationRequest
	root    *resourcev4.Root
	server  *httptest.Server
	arrived atomic.Int32
	data    atomic.Int32
}

func webSocketFactoryTest(t *testing.T, pin bool, handler ...func(*webSocketFactoryFixture, http.ResponseWriter, *http.Request)) *webSocketFactoryFixture {
	t.Helper()
	f := new(webSocketFactoryFixture)
	clock := sessionTestClock(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.UnixMilli(1000), NotAfter: time.UnixMilli(200000),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		f.arrived.Add(1)
		if request.URL.Path != "/flowersec/v4/direct" || request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Sec-WebSocket-Extensions") != "" {
			t.Error("credential or route escaped preparation")
		}
		if len(handler) != 0 {
			handler[0](f, writer, request)
			return
		}
		upgrader := websocket.Upgrader{Subprotocols: []string{carrierws.SubprotocolDirect}}
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			_, _, err := connection.ReadMessage()
			if err != nil {
				return
			}
			f.data.Add(1)
		}
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	upstream.StartTLS()
	f.server = upstream
	t.Cleanup(upstream.Close)
	address := netip.MustParseAddrPort(strings.TrimPrefix(upstream.URL, "https://"))
	encode := func(schema string, fields ...protocolv4.Field) []byte {
		t.Helper()
		wire, err := protocolv4.EncodeMap(make([]byte, 16384), schema, fields)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	tlsFields := []protocolv4.Field{{Name: "mode", Number: 0}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}}
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	roots.AddCert(parsed)
	if pin {
		digest := sha256.Sum256(der)
		entry := encode("TLSPin", protocolv4.Field{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]},
			protocolv4.Field{Name: "not_before_ms", Number: 2000}, protocolv4.Field{Name: "not_after_ms", Number: 190000},
			protocolv4.Field{Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile})
		tlsFields[0].Number = 1
		tlsFields = append(tlsFields, protocolv4.Field{Name: "pin_kind", Number: 0}, protocolv4.Field{Name: "pins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, entry...)})
		roots = nil
	}
	policy := encode("TLSPolicy", tlsFields...)
	leg := encode("Leg", protocolv4.Field{Name: "access_class"}, protocolv4.Field{Name: "leg_id", Kind: protocolv4.ByteString, Bytes: make([]byte, 16)},
		protocolv4.Field{Name: "endpoint_role", Number: 1}, protocolv4.Field{Name: "dialer_role"}, protocolv4.Field{Name: "listener_role", Number: 1},
		protocolv4.Field{Name: "carrier", Number: 1}, protocolv4.Field{Name: "host", Kind: protocolv4.TextString, Text: "127.0.0.1"},
		protocolv4.Field{Name: "port", Number: uint64(address.Port())}, protocolv4.Field{Name: "path", Kind: protocolv4.TextString, Text: "/flowersec/v4/direct"},
		protocolv4.Field{Name: "alpn", Kind: protocolv4.TextString, Text: "http/1.1"},
		protocolv4.Field{Name: "subprotocol", Kind: protocolv4.TextString, Text: carrierws.SubprotocolDirect},
		protocolv4.Field{Name: "tls_policy", Kind: protocolv4.EncodedMap, Bytes: policy})
	candidateID := [16]byte{77}
	route := encode("Route", protocolv4.Field{Name: "path_kind"}, protocolv4.Field{Name: "candidate_id", Kind: protocolv4.ByteString, Bytes: candidateID[:]}, protocolv4.Field{Name: "direct_leg", Kind: protocolv4.EncodedMap, Bytes: leg})
	limit := resourcev4.Vector{}
	for index := range limit {
		limit[index] = 1 << 30
	}
	f.root, err = resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 128})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.root.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	environment, err := f.root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	config := WebSocketFactoryConfig{Root: f.root, Owner: owner, Clock: clock, Route: route, RemoteAddress: address, Roots: roots, Connections: 1, RuntimeBytes: 65536,
		Options: carrierws.Options{MaxMessageBytes: 65536, ReadBufferBytes: 4096, WriteBufferBytes: 4096, HandshakeBytes: 8192, MaxControlsPerSecond: 8,
			HandshakeTimeout: time.Second, MessageTimeout: time.Second, RuntimeBytes: 8192, ProviderRuntimeBytes: 65536, ProviderTasks: 4}}
	charge, err := WebSocketCarrierFactoryCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := f.root.Reserve(admissionResourceKey(owner, 2), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reservation.Release)
	f.factory, err = NewWebSocketCarrierFactory(config, reservation, environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.factory.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.factory.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	scope := corePlanTestScope(t, f.root, limit, 1)
	charge, err = sessionv4.PreparedCarrierCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err = f.root.Reserve(admissionResourceKey(owner, 3), charge, scope.Tenant, scope.Session)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reservation.Release)
	deadline, err := timev4.NewAge(clock, 10000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte("flowersec/v4/route\x00"))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(route)))
	hash.Write(size[:])
	hash.Write(route)
	member := protocolv4.PoolMember{CandidateID: candidateID}
	copy(member.RouteDigest[:], hash.Sum(nil))
	f.request = sessionv4.CarrierPreparationRequest{Config: sessionv4.PreparedCarrierConfig{Candidate: member, Attempt: [16]byte{44},
		Session: testSessionContract(t, protocolv4.DHProfileX25519, "transport", 4096, 4, 0, ^uint64(0)),
		Role:    protocolv4.ClientToServer, Deadline: deadline, Reservation: reservation, Environment: environment, RuntimeBytes: 8192},
		Scope: scope, Route: route, Budget: sessionv4.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}}
	return f
}

func TestWebSocketFactoryNativeTLSAndOriginalOwnership(t *testing.T) {
	for _, pin := range []bool{false, true} {
		t.Run(strconv.FormatBool(pin), func(t *testing.T) {
			f := webSocketFactoryTest(t, pin)
			before := f.root.Snapshot().Charged
			prepared, err := f.factory.PrepareCarrier(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			cleanupPreparedTest(t, prepared)
			if prepared.Check() != nil || f.arrived.Load() != 1 || f.data.Load() != 0 {
				t.Fatal("preparation failed or published a Flowersec credential")
			}
			if f.root.Snapshot().Charged[resourcev4.Connections] != before[resourcev4.Connections]+1 {
				t.Fatal("native connection was not charged")
			}
			f.factory.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			if err := f.factory.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("factory refunded a live returned carrier", err)
			}
			if prepared.Check() != nil {
				t.Fatal("factory closure invalidated an independently owned carrier")
			}
			_ = prepared.Close()
			if err := prepared.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := prepared.Retire(); err != nil {
				t.Fatal(err)
			}
			if err := f.factory.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWebSocketFactoryBindingAndScopeRefusedBeforeNetwork(t *testing.T) {
	for _, failure := range []string{"route", "candidate", "scope", "address attempt", "deadline", "frame", "contract", "profile", "artifact", "attempt"} {
		t.Run(failure, func(t *testing.T) {
			f := webSocketFactoryTest(t, false)
			request := f.request
			switch failure {
			case "route":
				request.Route = append([]byte(nil), request.Route...)
				request.Route[len(request.Route)-1] ^= 1
			case "candidate":
				request.Config.Candidate.RouteDigest[0] ^= 1
			case "scope":
				request.Scope = sessionv4.SessionResourceScope{}
			case "address attempt":
				request.AddressAttempt = 1
			case "deadline":
				request.Config.Deadline.Cancel()
			case "frame":
				request.Config.Session = testSessionContract(t, protocolv4.DHProfileX25519, "transport", 65536, 4, 0, ^uint64(0))
			case "contract":
				request.Config.Session.Contract = protocolv4.SessionContract{}
			case "profile":
				request.Config.Session.Profile = "unknown"
			case "artifact":
				request.Config.Session.ArtifactDigest = [32]byte{}
			case "attempt":
				request.Config.Attempt = [16]byte{}
			}
			before := f.root.Snapshot().Charged
			if prepared, err := f.factory.PrepareCarrier(context.Background(), request); err == nil || prepared != nil {
				t.Fatal("invalid preparation reached carrier ownership", err)
			} else if failure == "address attempt" && err != native.ErrAddressesExhausted {
				t.Fatal("numeric inventory changed failure classification", err)
			}
			if f.arrived.Load() != 0 || f.root.Snapshot().Charged != before || request.Config.Reservation.Check() != nil {
				t.Fatal("local refusal used network or consumed caller backing")
			}
		})
	}
}

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

func corePlanTestScope(t *testing.T, root *resourcev4.Root, limit resourcev4.Vector, sessionID byte) sessionv4.SessionResourceScope {
	t.Helper()
	tenant, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte{1}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	sessionLimit := limit
	sessionLimit[resourcev4.Sessions] = 1
	session, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{sessionID}}, sessionLimit)
	if err != nil {
		t.Fatal(err)
	}
	return sessionv4.SessionResourceScope{Tenant: tenant, Session: session}
}

func cleanupPreparedTest(t *testing.T, p *sessionv4.PreparedCarrier) {
	t.Helper()
	t.Cleanup(func() {
		_ = p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
}

func admissionResourceKey(owner resourcev4.OwnerKey, position uint32) resourcev4.OwnerKey {
	var identity [20]byte
	copy(identity[:16], owner.Backing[:])
	binary.BigEndian.PutUint32(identity[16:], position)
	digest := sha256.Sum256(identity[:])
	copy(owner.Backing[:], digest[:16])
	return owner
}

func sessionTestClock(t *testing.T) *timev4.Clock {
	t.Helper()
	origin := time.Now()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Numerator: 1, Denominator: 10000, QuantizationMS: 2}, MaxWidthMS: 2000, MaxAgeMS: 3600000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: uint64(time.Since(origin) / time.Millisecond), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100000, UpperMS: 100000}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	return clock
}
