package controlv4

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type boundedControlSigner struct {
	key   ed25519.PrivateKey
	calls int
}

func (s *boundedControlSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }
func (s *boundedControlSigner) Sign(message []byte) ([]byte, error) {
	s.calls++
	return ed25519.Sign(s.key, message), nil
}

func TestRegisteredControlBoundsSigningInputBeforeProvider(t *testing.T) {
	signer := &boundedControlSigner{key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
	incarnation := make([]byte, 32)
	incarnation[0] = 1
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RegisteredControlReply{Incarnation: base64.StdEncoding.EncodeToString(incarnation), Authority: "authority-1"})
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	config := RegisteredControlConfig{Authority: "authority-1", Parent: [32]byte{1}, Incarnation: incarnation, Identity: signer, RuntimeBytes: 65536,
		HTTPS: HTTPSBootstrapConfig{BaseURL: server.URL + "/flowersec/control/tunnel", RemoteAddress: netip.MustParseAddrPort(server.Listener.Addr().String()),
			TLS: &tls.Config{RootCAs: roots, Certificates: server.TLS.Certificates}, HeaderBytes: 1024, Timeout: time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20}}
	charge, err := RegisteredControlTransportCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	providerCharge, err := HTTPSBootstrapCharge(config.HTTPS)
	if err != nil {
		t.Fatal(err)
	}
	var limit resourcev4.Vector
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	reserve := func(id byte, cost resourcev4.Vector) resourcev4.Reference {
		ref, err := root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{id}, Backing: [16]byte{id}, Kind: 1}, cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	p, err := NewRegisteredControlTransport(config, reserve(1, charge), reserve(2, providerCharge), reserve(3, resourcev4.Vector{resourcev4.SDKBytes: 4096}))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	guard := func() error { return nil }
	if _, err = p.CallTunnel(context.Background(), p.Payload("prepare"), guard); err != nil || signer.calls != 1 || requests.Load() != 1 {
		t.Fatal("bounded original call did not reach its signer and HTTPS peer", err, signer.calls, requests.Load())
	}
	for _, extra := range []int{0, 1} {
		payload := p.Payload("prepared_ack")
		payload.Recipient = "x"
		base, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		payload.Recipient = strings.Repeat("x", registeredControlBodyLimit-len(registeredControlDomain)-len(base)+1+extra)
		before := signer.calls
		if _, err = p.CallTunnel(context.Background(), payload, guard); !errors.Is(err, ErrResponse) {
			t.Fatal("oversized envelope was not rejected", extra, err)
		}
		wantCalls := before
		if extra == 0 {
			// The exact signing bound is valid, but its outer JSON envelope
			// remains too large to publish. One byte more must not be signed.
			wantCalls++
		}
		if signer.calls != wantCalls || requests.Load() != 1 {
			t.Fatal("signing or network boundary was not preserved", extra, signer.calls, wantCalls, requests.Load())
		}
	}
	payload := p.Payload("prepared_ack")
	payload.Recipient = strings.Repeat("\x00", registeredControlBodyLimit/6+1)
	before := signer.calls
	if _, err = p.CallTunnel(context.Background(), payload, guard); !errors.Is(err, ErrResponse) || signer.calls != before || requests.Load() != 1 {
		t.Fatal("JSON expansion bypassed the signing bound", err, signer.calls, requests.Load())
	}
	if _, err = p.CallTunnel(context.Background(), p.Payload("prepare"), guard); err != nil || signer.calls != before+1 || requests.Load() != 2 {
		t.Fatal("rejected payload retained the original call position", err, signer.calls, requests.Load())
	}
}
