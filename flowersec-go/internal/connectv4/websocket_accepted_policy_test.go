package connectv4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	ws "github.com/gorilla/websocket"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The credential originates from the common Artifact shape and is signed with
// the exact real listener tuple and policy. These tests exercise physical
// binding, not independent namespace issuer authorization.
func acceptedPolicyArtifact(t *testing.T, address string, policy []byte, host string, originPolicy []byte) *protocolv4.SignedMap {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.ParseUint(u.Port(), 10, 16)
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	var wire []byte
	for _, v := range corpus.Vectors {
		if v.ID == "artifact_transport_fields" {
			wire, err = hex.DecodeString(v.Hex)
		}
	}
	if err != nil || wire == nil {
		t.Fatal("shared artifact fixture", err)
	}
	d, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := d.DecodeShape(wire, "Artifact", protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	var registry struct {
		Maps map[string]struct {
			Fields map[string]struct{ Name, Type string }
		} `json:"frame_maps"`
	}
	if err := json.Unmarshal([]byte(protocolv4.CBORSyntaxRegistryJSON), &registry); err != nil {
		t.Fatal(err)
	}
	fields := func(schema string, value protocolv4.Value, changes map[string]protocolv4.Field, omit map[string]bool) []protocolv4.Field {
		var result []protocolv4.Field
		for _, spec := range registry.Maps[schema].Fields {
			if omit[spec.Name] || spec.Name == "signature" {
				continue
			}
			if field, ok := changes[spec.Name]; ok {
				field.Name = spec.Name
				result = append(result, field)
				continue
			}
			v := value.Named(schema, spec.Name)
			if len(v.Encoded()) == 0 {
				continue
			}
			field := protocolv4.Field{Name: spec.Name}
			switch spec.Type {
			case "bytes":
				field.Kind = protocolv4.ByteString
				field.Bytes, _ = v.ByteString()
			case "text":
				field.Kind = protocolv4.TextString
				field.Text, _ = v.Text()
			case "map":
				field.Kind, field.Bytes = protocolv4.EncodedMap, v.Encoded()
			case "array":
				field.Kind, field.Bytes = protocolv4.EncodedArray, v.Encoded()
			case "bool":
				field.Kind = protocolv4.Boolean
				b, _ := v.Bool()
				if b {
					field.Number = 1
				}
			default:
				field.Number, _ = v.Uint()
			}
			result = append(result, field)
		}
		return result
	}
	text := func(s string) protocolv4.Field { return protocolv4.Field{Kind: protocolv4.TextString, Text: s} }
	root := doc.Root()
	candidate := root.Named("Artifact", "candidates").Index(0)
	changes := map[string]protocolv4.Field{
		"access_class": {Number: 0}, "carrier": {Number: 1}, "host": text(host), "port": {Number: port},
		"path": text("/flowersec/v4/direct"), "subprotocol": text(websocket.SubprotocolDirect), "alpn": text("http/1.1"),
		"tls_policy": {Kind: protocolv4.EncodedMap, Bytes: policy},
	}
	omit := map[string]bool{"origin": true, "origin_policy": len(originPolicy) == 0}
	if len(originPolicy) > 0 {
		changes["origin_policy"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: originPolicy}
	}
	legFields := fields("Leg", candidate.Named("Candidate", "direct_leg"), changes, omit)
	leg, err := protocolv4.EncodeMap(make([]byte, 16384), "Leg", legFields)
	if err != nil {
		t.Fatal(err)
	}
	candidateWire, err := protocolv4.EncodeMap(make([]byte, 16384), "Candidate", fields("Candidate", candidate, map[string]protocolv4.Field{"direct_leg": {Kind: protocolv4.EncodedMap, Bytes: leg}}, nil))
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := codec.Sign(fields("Artifact", root, map[string]protocolv4.Field{"candidates": {Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, candidateWire...)}}, nil), [32]byte{71, 23, 4}, protocolv4.DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(artifact.Release)
	return artifact
}

func acceptedPolicyClock(t *testing.T, f *websocketServeFixture) *atomic.Uint64 {
	t.Helper()
	var tick atomic.Uint64
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Incarnation: [16]byte{1}, Milliseconds: tick.Load()}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, _ := clock.Monotonic()
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1000, UpperMS: 1100}); err != nil {
		t.Fatal(err)
	}
	f.clock = clock
	return &tick
}

func TestAcceptedWebSocketDefaultPolicyBindsActualLocalCertificate(t *testing.T) {
	for _, mode := range []string{"ca", "pin", "wrong_pin", "pin_expiry", "ca_missing_roots", "ca_wrong_san", "pin_different_san", "long_der", "signed_host_mismatch", "absent_origin", "allowed_origin", "denied_origin", "signed_origin_mismatch", "wrong_path", "factory"} {
		t.Run(mode, func(t *testing.T) {
			f := websocketServeTestOwner(t)
			tick := acceptedPolicyClock(t, f)
			days, san := 14, "accepted.example"
			if mode == "long_der" {
				days = 15
			}
			if mode == "ca_wrong_san" || mode == "pin_different_san" {
				san = "another.example"
			}
			der, key, roots := serverTLSCertificate(t, days, san)
			listener := newServerTLSListener(t, f, der, key)
			address := listener.Addr().String()
			u, _ := url.Parse("https://" + address)
			port, _ := strconv.ParseUint(u.Port(), 10, 16)
			p := WebSocketAcceptedPolicy{TLS: listener, Clock: f.clock, Roots: roots, Host: "accepted.example", Port: uint16(port), Path: "/flowersec/v4/direct", AllowAbsentOrigin: true}
			if mode == "ca_missing_roots" {
				p.Roots = nil
			}
			if mode == "absent_origin" || mode == "allowed_origin" || mode == "denied_origin" || mode == "signed_origin_mismatch" {
				p.AllowAbsentOrigin, p.Origins = false, []string{"https://app.example"}
			}
			cfg := f.accepted(t)
			cfg.Upgrade = websocket.UpgradeConfig{Subprotocol: websocket.SubprotocolDirect}
			cfg.DefaultPolicy = &p
			cfg.Options.MaxMessageBytes = protocolv4.MaxPayloadLength + protocolv4.EnvelopePrefixSize
			var appChecks atomic.Uint32
			cfg.Upgrade.CheckPolicy = func(*http.Request) error { appChecks.Add(1); return nil }
			cost, err := websocket.Charge(cfg.Options)
			if err != nil {
				t.Fatal(err)
			}
			cost, err = cost.Add(acceptedWebSocketPolicyCharge())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "factory" {
				cost, err = WebSocketAcceptedCharge(cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			reservation := f.reserve(t, cost)
			type result struct {
				messages *acceptedPolicyMessages
				entrance *sessionv4.AcceptedEntrance
				err      error
			}
			results := make(chan result, 1)
			server := &http.Server{ConnContext: listener.ConnContext, ConnState: listener.ConnState, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
			server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "factory" {
					factory, err := NewWebSocketAcceptedFactory(w, r, cfg, reservation)
					if err != nil {
						results <- result{err: err}
						return
					}
					entrance, err := factory.PrepareAccepted(context.Background(), cfg.Entrance.Initial.Deadline)
					factory.Close()
					_ = factory.WaitCleanup(context.Background())
					_ = factory.Retire()
					results <- result{entrance: entrance, err: err}
					return
				}
				backing, err := reservation.Borrow()
				if err != nil {
					results <- result{err: err}
					return
				}
				upgrade, m, err := p.upgrade(r, cfg.Upgrade, backing)
				if err == nil {
					m.Messages, err = websocket.Upgrade(context.Background(), w, r, upgrade, cfg.Options, reservation, f.shared)
				}
				if err != nil {
					backing.Release()
					reservation.Release()
					results <- result{err: err}
					return
				}
				results <- result{messages: m}
			})
			go func() { _ = server.Serve(listener) }()
			defer server.Close()
			dialer := ws.Dialer{TLSClientConfig: serverTLSClient(roots), Subprotocols: []string{websocket.SubprotocolDirect}, HandshakeTimeout: 2 * time.Second}
			// Certificate SAN is intentionally independent of pin authorization;
			// this external test peer trusts the actual SAN so server policy can
			// test its own exact signed hostname/DER constraints.
			dialer.TLSClientConfig.ServerName = san
			header := http.Header{"Host": {"accepted.example:" + u.Port()}}
			if mode == "allowed_origin" || mode == "signed_origin_mismatch" {
				header.Set("Origin", "https://app.example")
			}
			if mode == "denied_origin" {
				header.Set("Origin", "https://attacker.example")
			}
			path := "/flowersec/v4/direct"
			if mode == "wrong_path" {
				path = "/other"
			}
			peer, _, dialErr := dialer.Dial("wss://"+address+path, header)
			if peer != nil {
				defer peer.Close()
			}
			var got result
			select {
			case got = <-results:
			case <-time.After(3 * time.Second):
				t.Fatal("original upgrade did not finish", dialErr)
			}
			if mode == "absent_origin" || mode == "denied_origin" || mode == "wrong_path" {
				if dialErr == nil || got.err == nil || got.messages != nil || appChecks.Load() != 0 {
					t.Fatal("pre-upgrade policy bypass", dialErr, got.err)
				}
				return
			}
			if got.err != nil || dialErr != nil {
				t.Fatal(got.err, dialErr)
			}
			if mode == "factory" {
				if got.entrance == nil {
					t.Fatal("default factory did not transfer original entrance")
				}
				got.entrance.Close()
				_ = got.entrance.WaitCleanup(context.Background())
				_ = got.entrance.Retire()
				return
			}
			m := got.messages
			defer func() {
				_ = m.Close()
				_ = m.WaitCleanup(context.Background())
				if err := m.Retire(); err != nil {
					t.Error(err)
				}
			}()
			policy := policyMap(t, "TLSPolicy", protocolv4.Field{Name: "mode"}, protocolv4.Field{Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1})
			if mode == "pin" || mode == "pin_expiry" || mode == "wrong_pin" || mode == "long_der" || mode == "pin_different_san" {
				digest := sha256.Sum256(der)
				if mode == "wrong_pin" {
					digest[0] ^= 1
				}
				pin := policyMap(t, "TLSPin", protocolv4.Field{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]}, protocolv4.Field{Name: "not_before_ms"}, protocolv4.Field{Name: "not_after_ms", Number: 10000}, protocolv4.Field{Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile})
				policy = policyMap(t, "TLSPolicy", protocolv4.Field{Name: "mode", Number: 1}, protocolv4.Field{Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}, protocolv4.Field{Name: "pin_kind"}, protocolv4.Field{Name: "pins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, pin...)})
			}
			host := "accepted.example"
			if mode == "signed_host_mismatch" {
				host = "another.example"
			}
			var origins []byte
			if mode == "allowed_origin" {
				origins = policyMap(t, "OriginPolicy", protocolv4.Field{Name: "allow_absent", Kind: protocolv4.Boolean}, protocolv4.Field{Name: "origins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81, 0x73}, []byte("https://app.example")...)})
			}
			artifact := acceptedPolicyArtifact(t, "https://"+address, policy, host, origins)
			err = m.CheckAcceptedRoute(artifact, 0, protocolv4.HelloPolicy{BindingMode: 1})
			valid := mode == "ca" || mode == "pin" || mode == "pin_expiry" || mode == "pin_different_san" || mode == "allowed_origin"
			if (err == nil) != valid {
				t.Fatal("signed original policy result", err)
			}
			if !valid {
				return
			}
			if err = m.CheckAcceptedRoute(artifact, 0, protocolv4.HelloPolicy{BindingMode: 1}); err != nil {
				t.Fatal("same binding did not revalidate", err)
			}
			g, err := m.ConnectionGuarantees()
			if err != nil || g.LocalConsumerTls13Verification != protocolv4.V4ConsumerTLS13VerificationNotApplicable {
				t.Fatal("invented remote consumer evidence", g, err)
			}
			if mode == "pin_expiry" {
				tick.Store(9000)
				if _, err := m.ConnectionGuarantees(); !errors.Is(err, tlspolicy.ErrCertificate) {
					t.Fatal("expired matched pin remained eligible", err)
				}
				if err := m.CheckAcceptedRoute(artifact, 0, protocolv4.HelloPolicy{BindingMode: 1}); !errors.Is(err, tlspolicy.ErrCertificate) {
					t.Fatal("repeat refreshed original pin", err)
				}
			}
		})
	}
}
