package rawquic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func ownedTestPair(t *testing.T, managed ...bool) (*OwnedConnection, *OwnedConnection) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	limits := quicbase.DefaultLimits()
	limits.MaxInboundStreams = 4
	o := OwnedOptions{Limits: limits, StreamSlots: 4, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPNDirect},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	listener, err := Listen("127.0.0.1:0", tlsConfig, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	budget := resourcev4.Vector{}
	for i := range budget {
		budget[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: budget, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 32})
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	reserve := func(charge resourcev4.Vector) resourcev4.Reference {
		owner.Backing[0]++
		ref, err := root.Reserve(owner, charge)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	environment := reserve(resourcev4.Vector{resourcev4.SDKBytes: 1})
	t.Cleanup(func() {
		environment.Release()
		root.Close()
		if snapshot := root.Snapshot(); !snapshot.CleanupComplete {
			t.Error("native owners retained resources", snapshot)
		}
	})
	charge, err := OwnedCharge(o)
	if err != nil {
		t.Fatal(err)
	}
	var bounded *OwnedListener
	address := netip.MustParseAddrPort(listener.Addr().String())
	if len(managed) != 0 && managed[0] {
		account, err := root.Account(resourcev4.AccountKey{ID: [16]byte{1}, Kind: 1}, budget)
		if err != nil {
			t.Fatal(err)
		}
		c := OwnedListenerConfig{Root: root, Owner: owner, Accounts: []resourcev4.Account{account}, TLS: tlsConfig,
			Address: netip.MustParseAddrPort("127.0.0.1:0"), Connection: o, Connections: 1,
			RuntimeBytes: 65536, ProviderBytes: 1 << 20, ProviderTasks: 4}
		cost, err := OwnedListenerCharge(c)
		if err != nil {
			t.Fatal(err)
		}
		owner.Backing[0]++
		ref, err := root.Reserve(owner, cost, account)
		if err != nil {
			t.Fatal(err)
		}
		bounded, err = ListenOwned(c, ref, environment)
		ref.Release()
		if err != nil {
			t.Fatal(err)
		}
		address = bounded.Addr()
		t.Cleanup(func() {
			_ = bounded.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := bounded.WaitCleanup(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialOwned(ctx, address,
		&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPNDirect}, RootCAs: roots},
		o, 262144, 128, reserve(charge), environment)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func(p *OwnedConnection) {
		t.Cleanup(func() {
			_ = p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := p.WaitCleanup(ctx); err != nil {
				t.Error(err)
			}
			if err := p.Retire(); err != nil {
				t.Error(err)
			}
		})
	}
	cleanup(client)
	if bounded != nil {
		server, err := bounded.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cleanup(server)
		return client, server
	}
	native, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server, err := AcceptOwned(native, o, reserve(charge), environment)
	if err != nil {
		_ = native.Close()
		t.Fatal(err)
	}
	cleanup(server)
	if duplicate, err := AcceptOwned(native, o, resourcev4.Reference{}, environment); err == nil || duplicate != nil {
		t.Fatal("native connection was adopted twice")
	}
	return client, server
}

func retireTestStream(t *testing.T, s *OwnedStream) {
	t.Helper()
	t.Cleanup(func() {
		_ = s.Close()
		if err := s.Retire(); err != nil {
			t.Error(err)
		}
	})
}

func TestOwnedQUICNativeMaintenanceDuplexAndRetirement(t *testing.T) {
	client, server := ownedTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.OpenStream(ctx); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("data opened before original maintenance", err)
	}
	if _, err := server.OpenMaintenance(ctx); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("server opened client-owned maintenance", err)
	}
	if state, err := client.TLSState(); err != nil || state.NegotiatedProtocol != ALPNDirect || state.Version != tls.VersionTLS13 {
		t.Fatal("actual TLS observation unavailable", state, err)
	}
	left, err := client.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, left)
	if _, err := client.OpenMaintenance(ctx); err == nil {
		t.Fatal("original maintenance reissued")
	}
	if _, err := left.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	right, err := server.AcceptMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, right)
	var got [5]byte
	if _, err := io.ReadFull(right, got[:]); err != nil || string(got[:]) != "hello" {
		t.Fatal(got, err)
	}
	if err := left.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Read(got[:]); err != io.EOF {
		t.Fatal("native half-close did not end only that direction", err)
	}
	if _, err := right.Write([]byte("reply")); err != nil {
		t.Fatal("reverse direction failed after half-close", err)
	}
	if _, err := io.ReadFull(left, got[:]); err != nil || string(got[:]) != "reply" {
		t.Fatal(got, err)
	}
	data, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, peer)
	if _, err := io.ReadFull(peer, got[:4]); err != nil || string(got[:4]) != "data" {
		t.Fatal(got, err)
	}
	if err := data.Close(); err != nil {
		t.Fatal(err)
	}
	if err := data.Retire(); err != nil {
		t.Fatal(err)
	}
	replacement, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, replacement)
	if _, err := data.Write([]byte("stale")); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("retired handle used replacement stream", err)
	}
	if err := client.SendDatagram([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1024)
	if n, err := server.ReceiveDatagram(ctx, packet); err != nil || string(packet[:n]) != "packet" {
		t.Fatal(n, err)
	}
}

func TestOwnedQUICCloseJoinsBlockedNativeMethodAndKeepsStreamCharge(t *testing.T) {
	client, server := ownedTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	left, err := client.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, left)
	if _, err := left.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	right, err := server.AcceptMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, right)
	finished := make(chan error, 1)
	go func() { var b [1]byte; _, err := left.Read(b[:]); finished <- err }()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err == nil {
		t.Fatal("blocked read survived native close")
	}
	if err := client.Retire(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("retired provider before delivered streams", err)
	}
}

func TestOwnedQUICPreparationBudgetNeverResets(t *testing.T) {
	c := new(preparePacketConn)
	c.preparing.Store(true)
	c.bytes.Store(4)
	c.work.Store(2)
	if err := c.charge(3); err != nil {
		t.Fatal(err)
	}
	if err := c.charge(2); !errors.Is(err, ErrPrepareBudget) {
		t.Fatal(err)
	}
	if err := c.charge(0); !errors.Is(err, ErrPrepareBudget) {
		t.Fatal("exhausted original preparation revived", err)
	}
}

func TestOwnedQUICListenerRetainsAcceptedProviderUntilOriginalRetirement(t *testing.T) {
	client, server := ownedTestPair(t, true)
	listener := server.listener
	if listener == nil {
		t.Fatal("lost original listener")
	}
	listener.mu.Lock()
	if len(listener.slots) != 1 || !listener.slots[0].used {
		t.Fatal("accepted provider did not retain position")
	}
	listener.mu.Unlock()
	// Admission happens before TLS, even though nobody calls Accept for this
	// second connection. It cannot exceed the fixed listener connection table.
	ctxAttempt, cancelAttempt := context.WithTimeout(context.Background(), time.Second)
	defer cancelAttempt()
	second, err := Dial(ctxAttempt, listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPNDirect}, InsecureSkipVerify: true,
		VerifyConnection: func(tls.ConnectionState) error {
			t.Error("over-capacity peer reached TLS verification")
			return resourcev4.ErrCapacity
		}}, listener.c.Connection.Limits)
	if second != nil || err == nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("listener created an unadmitted second connection", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := listener.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("listener refunded accepted provider", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := server.Retire(); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := listener.WaitCleanup(ctx2); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
}

func TestOwnedQUICListenerRejectsDynamicOrCredentialTLSConfig(t *testing.T) {
	_, server := ownedTestPair(t, true)
	c := server.listener.c
	for _, mutation := range []func(*tls.Config){
		func(c *tls.Config) {
			c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
		},
		func(c *tls.Config) { c.ClientAuth = tls.RequireAnyClientCert },
		func(c *tls.Config) { c.NextProtos = []string{ALPNDirect, ALPNTunnel} },
	} {
		clone := c.TLS.Clone()
		mutation(clone)
		invalid := c
		invalid.TLS = clone
		if _, err := OwnedListenerCharge(invalid); err == nil {
			t.Fatal("accepted mutable/credential TLS preparation")
		}
	}
}

func TestOwnedQUICAdoptionFencesRawAliases(t *testing.T) {
	client, server := ownedTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, p := range []*OwnedConnection{client, server} {
		if _, err := p.session.OpenStream(ctx); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("raw open bypassed ownership", err)
		}
		if _, err := p.session.AcceptStream(ctx); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("raw accept bypassed ownership", err)
		}
		if err := p.session.SendUnreliable([]byte{1}); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("raw datagram bypassed ownership", err)
		}
		if _, err := p.session.ReceiveUnreliable(ctx); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("raw receive bypassed ownership", err)
		}
		if err := p.session.Close(); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("raw close bypassed ownership", err)
		}
	}
	left, err := client.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, left)
	if _, err = left.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	right, err := server.AcceptMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retireTestStream(t, right)
	var byteValue [1]byte
	if _, err = io.ReadFull(right, byteValue[:]); err != nil {
		t.Fatal(err)
	}
	if err = left.ResetWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = right.Read(byteValue[:]); err == nil {
		t.Fatal("send reset did not reach peer")
	}
	if _, err = right.Write([]byte{2}); err != nil {
		t.Fatal("send reset ended reverse direction", err)
	}
	if _, err = io.ReadFull(left, byteValue[:]); err != nil || byteValue[0] != 2 {
		t.Fatal("reverse read after reset", err)
	}
	if err = left.Close(); err != nil {
		t.Fatal(err)
	}
	if err = left.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}
