package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPrepareBudgetBoundsActualTLSBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	options := testOptions()
	charge, _ := Charge(options)
	root, ref, environment := reservations(t, charge)
	config := DialConfig{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/flowersec/v4/direct", RemoteAddress: preparedAddress(t, server.URL), Subprotocol: SubprotocolDirect, TLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), PrepareBytes: 32, CheckPolicy: func(*url.URL, netip.AddrPort, http.Header) error { return nil }}
	before := root.Snapshot()
	messages, err := Dial(context.Background(), config, options, ref, environment)
	if messages != nil || !errors.Is(err, ErrPrepareBytes) || requests.Load() != 0 {
		t.Fatal("TLS escaped original byte budget", err, requests.Load())
	}
	after := root.Snapshot()
	if after.Charged[0] >= before.Charged[0] {
		t.Fatal("failed actual TLS preparation did not retire")
	}
}

func TestPrepareBudgetSharesReadAndWriteAllowance(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &ownedConn{Conn: left}
	c.preparing.Store(true)
	c.prepareRemaining.Store(5)
	peer := make(chan error, 1)
	go func() {
		if _, err := right.Write([]byte{1, 2, 3}); err != nil {
			peer <- err
			return
		}
		b := make([]byte, 2)
		_, err := io.ReadFull(right, b)
		peer <- err
	}()
	if n, err := c.Read(make([]byte, 8)); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := c.Write([]byte{4, 5, 6}); n != 2 || !errors.Is(err, ErrPrepareBytes) {
		t.Fatal(n, err)
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrPrepareBytes) {
		t.Fatal(n, err)
	}
	c.preparing.Store(false)
	go func() { _, err := right.Write([]byte{7}); peer <- err }()
	if n, err := c.Read(make([]byte, 1)); n != 1 || err != nil {
		t.Fatal("installed carrier retained preparation cap", n, err)
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
}
