package webtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	wt "github.com/quic-go/webtransport-go"
)

func nativeRequest(protocol string) *http.Request {
	r := &http.Request{Method: http.MethodConnect, Proto: protocol, URL: &url.URL{Scheme: "https", Host: "localhost", Path: PathDirect}, Header: make(http.Header)}
	return r
}

func TestNativeTupleRequiresWholeRequestAndSettings(t *testing.T) {
	for _, protocol := range []string{"webtransport-h3", "webtransport"} {
		t.Run(protocol, func(t *testing.T) {
			r := nativeRequest(protocol)
			if protocol == "webtransport" {
				r.Header.Set("Sec-Webtransport-Http3-Draft02", "1")
			}
			tuple := requestTuple(r)
			if tuple == nil {
				t.Fatal("registered tuple rejected")
			}
			settings := &http3.Settings{EnableDatagrams: true, Other: make(map[uint64]uint64)}
			for id, value := range tuple.RequiredPeerSettings {
				settings.Other[id] = value
			}
			if err := tuple.checkSettings(settings); err != nil {
				t.Fatal(err)
			}
			for _, id := range nativeProfiles.ForbiddenPeerSettings {
				for _, value := range []uint64{0, 1024} {
					settings.Other[id] = value
					if tuple.checkSettings(settings) == nil {
						t.Fatal("accepted WT session-level flow-control settings", id, value)
					}
				}
				delete(settings.Other, id)
			}
			settings.EnableDatagrams = false
			if tuple.checkSettings(settings) == nil {
				t.Fatal("accepted non-RFC datagram path")
			}
			settings.EnableDatagrams = true
			for id := range tuple.RequiredPeerSettings {
				delete(settings.Other, id)
				if tuple.checkSettings(settings) == nil {
					t.Fatal("accepted protocol string without peer setting")
				}
			}
		})
	}
	for name, mutate := range map[string]func(*http.Request){
		"old_path":             func(r *http.Request) { r.URL.Path = "/flowersec/webtransport/v3/direct" },
		"query":                func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"empty_query":          func(r *http.Request) { r.URL.ForceQuery = true },
		"fragment":             func(r *http.Request) { r.URL.Fragment = "x" },
		"raw_path":             func(r *http.Request) { r.URL.RawPath = PathDirect },
		"capsule":              func(r *http.Request) { r.Header.Set("Capsule-Protocol", "?1") },
		"subprotocol":          func(r *http.Request) { r.Header.Set("WT-Available-Protocols", `"flowersec"`) },
		"missing_header":       func(r *http.Request) { r.Header.Del("Sec-Webtransport-Http3-Draft02") },
		"wrong_header":         func(r *http.Request) { r.Header.Set("Sec-Webtransport-Http3-Draft02", "0") },
		"duplicate_header":     func(r *http.Request) { r.Header.Add("Sec-Webtransport-Http3-Draft02", "1") },
		"mixed_case_duplicate": func(r *http.Request) { r.Header["sec-webtransport-http3-draft02"] = []string{"1"} },
		"combined_header":      func(r *http.Request) { r.Header.Set("Sec-Webtransport-Http3-Draft02", "1, 1") },
		"mixed_tuple":          func(r *http.Request) { r.Proto = "webtransport-h3" },
		"unsupported_protocol": func(r *http.Request) { r.Proto = "webtransport-capsule" },
	} {
		t.Run(name, func(t *testing.T) {
			r := nativeRequest("webtransport")
			r.Header.Set("Sec-Webtransport-Http3-Draft02", "1")
			if !validUpgradeRequest(r) {
				t.Fatal("negative test did not start from a supported tuple")
			}
			mutate(r)
			if validUpgradeRequest(r) {
				t.Fatal("accepted invalid request tuple")
			}
		})
	}
}

func tupleTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1"}
}

func TestNativeTupleDedicatedConnectionAndDialerAdmission(t *testing.T) {
	serverTLS, clientTLS := tupleTLS(t)
	server, err := NewServer(serverTLS, quicbase.DefaultLimits(), func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *Session, 2)
	server.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := server.Upgrade(w, r)
		if err != nil {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		accepted <- s
	}))
	served := make(chan error, 1)
	go func() { served <- server.Serve(packet) }()
	t.Cleanup(func() { _ = server.Close(); _ = packet.Close(); <-served })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config, err := newQUICConfig(quicbase.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	connection, err := quic.DialAddr(ctx, packet.LocalAddr().String(), clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "")
	transport := &wt.Transport{}
	client, err := transport.NewClientConn(connection)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	endpoint := "https://" + packet.LocalAddr().String() + PathDirect
	_, native, err := client.Dial(ctx, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer native.CloseWithError(0, "")
	local, err := wrapSession(native, 16, "direct")
	if err != nil {
		t.Fatal(err)
	}
	remote := <-accepted
	stream, err := OpenAdmissionStream(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Reset()
	if _, err = stream.Write([]byte("FSB4")); err != nil {
		t.Fatal(err)
	}
	incoming, err := AcceptAdmissionStream(ctx, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Reset()
	var first [4]byte
	if _, err = io.ReadFull(incoming, first[:]); err != nil || string(first[:]) != "FSB4" {
		t.Fatal("provider leaked native prefix", first, err)
	}
	if _, second, err := client.Dial(ctx, endpoint, nil); err == nil || second != nil {
		t.Fatal("accepted second Session on dedicated connection")
	}
}
