package webtransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// The test advances the actual native stream allocator before CONNECT. No
// production hook overrides an ID, TLS state, or session exporter result.
func ownedWTExporterPair(t *testing.T, nonzero bool) (*OwnedConnection, *OwnedConnection) {
	t.Helper()
	serverTLS, clientTLS := tupleTLS(t)
	serverTLS.NextProtos, clientTLS.NextProtos = []string{http3.NextProtoH3}, []string{http3.NextProtoH3}
	serverTLS.SessionTicketsDisabled, clientTLS.SessionTicketsDisabled = true, true
	limits := quicbase.DefaultLimits()
	limits.MaxInboundStreams = 4
	options := OwnedOptions{Limits: limits, StreamSlots: 4, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	var budget resourcev4.Vector
	for i := range budget {
		budget[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: budget, AccountSlots: 4, ReservationSlots: 16, ReferenceSlots: 64})
	if err != nil {
		t.Fatal(err)
	}
	account, err := root.Account(resourcev4.AccountKey{ID: [16]byte{1}, Kind: 1}, budget)
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	reserve := func(charge resourcev4.Vector) resourcev4.Reference {
		owner.Backing[0]++
		ref, err := root.Reserve(owner, charge, account)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	environment := reserve(resourcev4.Vector{resourcev4.SDKBytes: 1})
	t.Cleanup(func() {
		environment.Release()
		root.Close()
		if snapshot := root.Snapshot(); !snapshot.CleanupComplete {
			t.Error("retained native exporter resources", snapshot)
		}
	})
	c := OwnedListenerConfig{Root: root, Owner: owner, Accounts: []resourcev4.Account{account}, TLS: serverTLS,
		CheckOrigin: func(*http.Request) bool { return true }, CheckRequest: func(*http.Request) bool { return true },
		Address: netip.MustParseAddrPort("127.0.0.1:0"), Connection: options, Connections: 1,
		RuntimeBytes: 65536, ProviderBytes: 1 << 20, ProviderTasks: 4}
	cost, err := OwnedListenerCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	ref := reserve(cost)
	listener, err := ListenOwned(c, ref, environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := listener.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	cost, err = OwnedCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newOwned(options, reserve(cost), environment)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func(p *OwnedConnection) {
		t.Cleanup(func() {
			_ = p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	cleanup(client)
	client.client = true
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	client.packet, client.transport = socket, &quic.Transport{Conn: socket}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconfig, err := newQUICConfig(options.Limits)
	if err != nil {
		t.Fatal(err)
	}
	client.conn, err = client.transport.Dial(ctx, net.UDPAddrFromAddrPort(listener.Addr()), clientTLS, qconfig)
	if err != nil {
		t.Fatal(err)
	}
	if nonzero {
		unused, err := client.conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		unused.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		unused.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	endpoint, err := url.Parse("https://" + listener.Addr().String() + PathDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.connectNative(ctx, endpoint, ""); err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(server)
	return client, server
}

func TestOwnedWebTransportExporterActualCONNECTAndTLS(t *testing.T) {
	for _, nonzero := range []bool{false, true} {
		name := "zero"
		if nonzero {
			name = "nonzero"
		}
		t.Run(name, func(t *testing.T) {
			client, server := ownedWTExporterPair(t, nonzero)
			wantID := uint64(0)
			if nonzero {
				wantID = 4
			}
			if client.session.id != wantID || server.session.id != wantID {
				t.Fatal("CONNECT did not use actual allocated ID")
			}
			artifact := [32]byte{1, 4, 9}
			left, err := client.ExportBinding(artifact)
			if err != nil {
				t.Fatal(err)
			}
			right, err := server.ExportBinding(artifact)
			if err != nil || left != right || left == ([32]byte{}) {
				t.Fatal("original WT peer exporters differ", err)
			}
			state, err := client.TLSState()
			if err != nil {
				t.Fatal(err)
			}
			var wrapper [63]byte
			binary.BigEndian.PutUint64(wrapper[:8], wantID)
			wrapper[8] = 21
			copy(wrapper[9:30], "EXPORTER-flowersec-v4")
			wrapper[30] = 32
			copy(wrapper[31:], artifact[:])
			exact, err := state.ExportKeyingMaterial("EXPORTER-WebTransport", wrapper[:], 32)
			if err != nil || !bytes.Equal(exact, left[:]) {
				t.Fatal("WT session wrapper inputs changed", err)
			}
			checkDifferent := func(label string, context []byte) {
				t.Helper()
				value, err := state.ExportKeyingMaterial(label, context, 32)
				if err != nil || bytes.Equal(value, left[:]) {
					t.Fatal("exporter domain or context not separated", err)
				}
			}
			checkDifferent("EXPORTER-flowersec-v4", artifact[:])
			checkDifferent("EXPORTER-EXPORTER-WebTransport", wrapper[:])
			binary.BigEndian.PutUint64(wrapper[:8], wantID+4)
			checkDifferent("EXPORTER-WebTransport", wrapper[:])
			binary.BigEndian.PutUint64(wrapper[:8], wantID)
			wrapper[31]++
			checkDifferent("EXPORTER-WebTransport", wrapper[:])
			if state.Version != tls.VersionTLS13 {
				t.Fatal("not actual TLS 1.3")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := client.ExportBinding(artifact); err == nil {
				t.Fatal("closed WT reused exporter authority")
			}
		})
	}
}
