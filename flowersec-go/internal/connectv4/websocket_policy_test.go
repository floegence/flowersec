package connectv4

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	ws "github.com/gorilla/websocket"
)

func policyMap(t *testing.T, schema string, fields ...protocolv4.Field) []byte {
	t.Helper()
	wire, err := protocolv4.EncodeMap(make([]byte, 16384), schema, fields)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func policyTestSession(t *testing.T) protocolv4.ArtifactSessionParameters {
	t.Helper()
	var corpus struct {
		Vectors []struct{ Schema, Hex, Kind string }
	}
	wire, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil || json.Unmarshal(wire, &corpus) != nil {
		t.Fatal("read original contract fixture", err)
	}
	for _, v := range corpus.Vectors {
		if v.Schema != "SessionContract" || v.Kind != "cbor_fields" {
			continue
		}
		data, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		decoder, _ := protocolv4.NewDecoder(65536, 4096)
		doc, err := decoder.DecodeMap(data, "SessionContract", protocolv4.DecodeContext{})
		if err != nil {
			t.Fatal(err)
		}
		defer doc.Release()
		contract, err := doc.SessionContract()
		if err != nil {
			t.Fatal(err)
		}
		return protocolv4.ArtifactSessionParameters{Contract: contract, ArtifactDigest: [32]byte{1}, Profile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", IssuedAtMS: 1000, SessionNotAfterMS: 4000}
	}
	t.Fatal("missing contract fixture")
	return protocolv4.ArtifactSessionParameters{}
}

func TestWebSocketDefaultPolicyActualTLSAndOriginalExpiry(t *testing.T) {
	for _, mode := range []string{"ca", "ca_wrong_san", "ca_no_roots", "pin", "pin_other_san", "wrong_pin", "long_der", "route_mismatch", "route_digest", "credential_header"} {
		t.Run(mode, func(t *testing.T) {
			const start = uint64(2000000000000)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			days := 14
			if mode == "long_der" {
				days = 15
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"authorized.example"},
				NotBefore: time.UnixMilli(int64(start)), NotAfter: time.UnixMilli(int64(start + uint64(days)*86400000)), BasicConstraintsValid: true,
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if mode == "ca_wrong_san" || mode == "pin_other_san" {
				template.DNSNames = []string{"another.example"}
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			certificate, _ := x509.ParseCertificate(der)
			peers := make(chan *ws.Conn, 1)
			var upgrades atomic.Uint32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upgrades.Add(1)
				conn, err := (&ws.Upgrader{Subprotocols: []string{websocket.SubprotocolDirect}}).Upgrade(w, r, nil)
				if err == nil {
					peers <- conn
				}
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"http/1.1"}}
			server.StartTLS()
			defer server.Close()
			u, _ := url.Parse(server.URL)
			address, _ := netip.ParseAddrPort(u.Host)
			var tick atomic.Uint64
			clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
				return timev4.Tick{Incarnation: [16]byte{1}, Milliseconds: tick.Load()}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clock.Close()
			mark, _ := clock.Monotonic()
			if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: start + 1000, UpperMS: start + 1100}); err != nil {
				t.Fatal(err)
			}
			deadline, _ := timev4.NewDeadline(clock, start+50000)
			roots := x509.NewCertPool()
			roots.AddCert(certificate)
			policy := policyMap(t, "TLSPolicy", protocolv4.Field{Name: "mode"}, protocolv4.Field{Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1})
			if !strings.HasPrefix(mode, "ca") {
				digest := sha256.Sum256(der)
				if mode == "wrong_pin" {
					digest[0] ^= 1
				}
				pin := policyMap(t, "TLSPin", protocolv4.Field{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]}, protocolv4.Field{Name: "not_before_ms", Number: start}, protocolv4.Field{Name: "not_after_ms", Number: start + 10000}, protocolv4.Field{Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile})
				policy = policyMap(t, "TLSPolicy", protocolv4.Field{Name: "mode", Number: 1}, protocolv4.Field{Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}, protocolv4.Field{Name: "pin_kind"}, protocolv4.Field{Name: "pins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, pin...)})
			}
			id := [16]byte{1}
			leg := policyMap(t, "Leg", protocolv4.Field{Name: "access_class"}, protocolv4.Field{Name: "leg_id", Kind: protocolv4.ByteString, Bytes: id[:]}, protocolv4.Field{Name: "endpoint_role", Number: 1}, protocolv4.Field{Name: "dialer_role"}, protocolv4.Field{Name: "listener_role", Number: 1}, protocolv4.Field{Name: "carrier", Number: 1}, protocolv4.Field{Name: "host", Kind: protocolv4.TextString, Text: "authorized.example"}, protocolv4.Field{Name: "port", Number: uint64(address.Port())}, protocolv4.Field{Name: "path", Kind: protocolv4.TextString, Text: "/flowersec/v4/direct"}, protocolv4.Field{Name: "alpn", Kind: protocolv4.TextString, Text: "http/1.1"}, protocolv4.Field{Name: "subprotocol", Kind: protocolv4.TextString, Text: websocket.SubprotocolDirect}, protocolv4.Field{Name: "tls_policy", Kind: protocolv4.EncodedMap, Bytes: policy})
			route := policyMap(t, "Route", protocolv4.Field{Name: "path_kind"}, protocolv4.Field{Name: "candidate_id", Kind: protocolv4.ByteString, Bytes: id[:]}, protocolv4.Field{Name: "direct_leg", Kind: protocolv4.EncodedMap, Bytes: leg})
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(route)))
			bytes := append([]byte("flowersec/v4/route\x00"), length[:]...)
			digest := sha256.Sum256(append(bytes, route...))
			limit := resourcev4.Vector{}
			for i := range limit {
				limit[i] = 1 << 28
			}
			root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 32})
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
			environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 8192, resourcev4.Items: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer environment.Release()
			owner.Backing[0] = 2
			cost, _ := sessionv4.PreparedCarrierCharge(8192)
			wrapper, err := root.Reserve(owner, cost)
			if err != nil {
				t.Fatal(err)
			}
			defer wrapper.Release()
			owner.Backing[0] = 3
			factory := WebSocketConsumerFactory{DefaultPolicy: &WebSocketPolicy{Clock: clock, Roots: roots}, PreparationWorkUnits: 128, Root: root, Owner: owner, Environment: environment,
				Options: websocket.Options{MaxMessageBytes: 4096, ReadBufferBytes: 125, WriteBufferBytes: 125, HandshakeBytes: 4096, MaxControlsPerSecond: 8, HandshakeTimeout: time.Second, MessageTimeout: time.Second, RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4},
				Dial:    websocket.DialConfig{URL: "wss://authorized.example:" + u.Port() + "/flowersec/v4/direct", RemoteAddress: address, Subprotocol: websocket.SubprotocolDirect}}
			request := sessionv4.CarrierPreparationRequest{Route: route, Budget: sessionv4.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, Config: sessionv4.PreparedCarrierConfig{Candidate: protocolv4.PoolMember{CandidateID: id, RouteDigest: digest}, Attempt: id, Session: policyTestSession(t), Role: protocolv4.ClientToServer, Deadline: deadline, Reservation: wrapper, Environment: environment, RuntimeBytes: 8192}}
			if mode == "route_mismatch" {
				factory.Dial.URL = strings.Replace(factory.Dial.URL, "authorized.example", "other.example", 1)
			}
			if mode == "credential_header" {
				factory.Dial.Header = http.Header{"Authorization": {"forbidden"}}
			}
			if mode == "route_digest" {
				request.Config.Candidate.RouteDigest[0] ^= 1
			}
			if mode == "ca_no_roots" {
				factory.DefaultPolicy.Roots = nil
			}
			before := root.Snapshot()
			prepared, err := factory.PrepareCarrier(context.Background(), request)
			if mode != "ca" && mode != "pin" && mode != "pin_other_san" {
				if err == nil || prepared != nil || root.Snapshot() != before || upgrades.Load() != 0 {
					t.Fatalf("invalid policy escaped or retained resources: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			peer := <-peers
			defer peer.Close()
			if err = prepared.Check(); err != nil {
				t.Fatal(err)
			}
			if mode == "pin" {
				tick.Store(9000)
				if err = prepared.Check(); !errors.Is(err, tlspolicy.ErrCertificate) {
					t.Fatal("expired original matched pin remained eligible", err)
				}
			}
			prepared.Close()
			if err = prepared.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = prepared.Retire(); err != nil {
				t.Fatal(err)
			}
			if root.Snapshot().Reservations != 1 {
				t.Fatal("policy backing outlived original cleanup")
			}
		})
	}
}
