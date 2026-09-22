package websocket

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	ws "github.com/gorilla/websocket"
)

// Build a valid signed local Artifact from the shared schema fixture. No
// production parser or trust check is bypassed by the observed-route tests.
func acceptedLocalArtifact(t *testing.T, address string) *protocolv4.SignedMap {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.ParseUint(u.Port(), 10, 16)
	raw, err := os.ReadFile("../../../../testdata/transport_v4/corpus.json")
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
	legFields := fields("Leg", candidate.Named("Candidate", "direct_leg"), map[string]protocolv4.Field{
		"access_class": {Number: 1}, "carrier": {Number: 1}, "host": text(u.Hostname()), "port": {Number: port}, "path": text("/flowersec/v4/local"), "subprotocol": text(SubprotocolLocal), "origin": text(address),
	}, map[string]bool{"tls_policy": true, "origin_policy": true, "alpn": true})
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

func TestAcceptedRouteOriginalUpgradeAndPolicyTail(t *testing.T) {
	o := testOptions()
	o.MaxMessageBytes = protocolv4.MaxPayloadLength + protocolv4.EnvelopePrefixSize
	charge, _ := Charge(o)
	root, ref, environment := reservations(t, charge)
	result := make(chan *Messages, 1)
	failures := make(chan error, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := Upgrade(r.Context(), w, r, UpgradeConfig{Subprotocol: SubprotocolLocal, CheckPolicy: func(*http.Request) error { return nil }, CheckAcceptedRoute: func(e protocolv4.AcceptedWebSocketEndpoint, _ *protocolv4.SignedMap, _ uint64, _ protocolv4.HelloPolicy) error {
			calls.Add(1)
			close(entered)
			<-release
			return nil
		}}, o, ref, environment)
		if err != nil {
			failures <- err
			return
		}
		r.Host = "changed.invalid"
		r.URL.Path = "/changed"
		r.Header.Set("Origin", "http://changed.invalid")
		result <- m
	}))
	defer server.Close()
	artifact := acceptedLocalArtifact(t, server.URL)
	dialer := ws.Dialer{Subprotocols: []string{SubprotocolLocal}}
	peer, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/flowersec/v4/local", http.Header{"Origin": {server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var m *Messages
	select {
	case m = <-result:
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("upgrade timeout")
	}
	cleanupMessages(t, m)
	_, _, foreignEnvironment := reservations(t, charge)
	if err := m.CheckEnvironment(environment); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckEnvironment(foreignEnvironment); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("foreign root accepted", err)
	}
	policy := protocolv4.HelloPolicy{BindingMode: 1}
	if err := artifact.CheckAcceptedWebSocket(0, m.acceptedEndpoint, policy); err != nil {
		t.Fatal("upgrade observations were not retained", err)
	}
	for _, field := range []string{"host", "port", "path", "subprotocol", "origin", "origin_absent", "tls", "local", "remote", "exporter", "mode"} {
		e, p := m.acceptedEndpoint, policy
		switch field {
		case "host":
			e.Host = "127.0.0.2"
		case "port":
			e.Port++
		case "path":
			e.Path += "/changed"
		case "subprotocol":
			e.Subprotocol = SubprotocolTunnel
		case "origin":
			e.Origin = "http://changed.invalid"
		case "origin_absent":
			e.OriginPresent = false
		case "tls":
			e.TLS13 = true
		case "local":
			e.Local = netip.MustParseAddrPort("192.0.2.1:1")
		case "remote":
			e.Remote = netip.MustParseAddrPort("192.0.2.2:1")
		case "exporter":
			p.Exporter = []byte{1}
		case "mode":
			p.BindingMode = 0
		}
		if artifact.CheckAcceptedWebSocket(0, e, p) == nil {
			t.Fatal("changed observation accepted", field)
		}
	}
	checked := make(chan error, 1)
	go func() { checked <- m.CheckAcceptedRoute(artifact, 0, policy) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original policy not called")
	}
	if err := m.CheckAcceptedRoute(artifact, 0, policy); !errors.Is(err, ErrConcurrent) {
		t.Fatal("duplicate policy call", err)
	}
	before := root.Snapshot().Charged
	_ = m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := m.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("policy tail abandoned", err)
	}
	if root.Snapshot().Charged != before {
		t.Fatal("policy call refunded early")
	}
	close(release)
	if err := <-checked; !errors.Is(err, net.ErrClosed) {
		t.Fatal("late policy success revived connection", err)
	}
	if err := m.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("policy called more than once")
	}
}

func TestAcceptedRouteCannotPromoteDialedProvider(t *testing.T) {
	m, _, _ := dialPair(t, testOptions())
	if err := m.CheckAcceptedRoute(nil, 0, protocolv4.HelloPolicy{}); !errors.Is(err, resourcev4.ErrConfiguration) {
		t.Fatal(err)
	}
}

func TestAcceptedRouteRejectsAmbiguousHTTPObservations(t *testing.T) {
	for _, variant := range []string{"duplicate_origin", "empty_origin", "query", "absolute", "userinfo", "tls12", "alpn"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:1234/flowersec/v4/local", nil)
		r.URL.Scheme, r.URL.Host = "", ""
		switch variant {
		case "duplicate_origin":
			r.Header["Origin"] = []string{"http://127.0.0.1:1234"}
			r.Header["origin"] = []string{"http://127.0.0.1:1234"}
		case "empty_origin":
			r.Header["Origin"] = []string{""}
		case "query":
			r.URL.RawQuery = "x=1"
		case "absolute":
			r.URL.Scheme, r.URL.Host = "http", "127.0.0.1:1234"
		case "userinfo":
			r.URL.User = url.User("user")
		case "tls12":
			r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12, NegotiatedProtocol: "http/1.1"}
		case "alpn":
			r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}
		}
		if _, err := ObserveAcceptedEndpoint(r, SubprotocolLocal); err == nil {
			t.Fatal("ambiguous request accepted", variant)
		}
	}
}

func TestAcceptedRouteRejectsInsufficientOriginalProviderCapacity(t *testing.T) {
	o := testOptions()
	charge, _ := Charge(o)
	_, ref, environment := reservations(t, charge)
	result := make(chan *Messages, 1)
	failures := make(chan error, 1)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := Upgrade(r.Context(), w, r, UpgradeConfig{Subprotocol: SubprotocolLocal, CheckPolicy: func(*http.Request) error { return nil }, CheckAcceptedRoute: func(protocolv4.AcceptedWebSocketEndpoint, *protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error {
			calls.Add(1)
			return nil
		}}, o, ref, environment)
		if err != nil {
			failures <- err
			return
		}
		result <- m
	}))
	defer server.Close()
	artifact := acceptedLocalArtifact(t, server.URL)
	dialer := ws.Dialer{Subprotocols: []string{SubprotocolLocal}}
	peer, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/flowersec/v4/local", http.Header{"Origin": {server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var m *Messages
	select {
	case m = <-result:
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("upgrade timeout")
	}
	cleanupMessages(t, m)
	if err := m.CheckAcceptedRoute(artifact, 0, protocolv4.HelloPolicy{BindingMode: 1}); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("undersized original provider accepted signed frame contract", err)
	}
	if calls.Load() != 0 {
		t.Fatal("capacity refusal reached deployment policy")
	}
}
