//go:build darwin || linux

package websocket

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type dialObserverContext struct {
	context.Context
	observers atomic.Int32
}

func (c *dialObserverContext) Value(any) any { return nil }
func (c *dialObserverContext) AfterFunc(func()) func() bool {
	c.observers.Add(1)
	return func() bool { return true }
}

// A real loopback listener with a full kernel accept queue leaves the next
// nonblocking TCP connect pending. Every filler connection has a test-owned
// close; no network service, resolver or privileged packet filter is needed.
func saturatedLoopback(t *testing.T) netip.AddrPort {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(address.(*unix.SockaddrInet4).Port))
	for range 16 {
		conn, err := connectNumeric(context.Background(), endpoint, time.Now().Add(30*time.Millisecond))
		if errors.Is(err, context.DeadlineExceeded) {
			return endpoint
		}
		if err != nil {
			t.Fatal("fill actual accept queue", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
	}
	t.Fatal("loopback accept queue did not reach its explicit bound")
	return netip.AddrPort{}
}

func TestNumericConnectCancellationAndDeadline(t *testing.T) {
	endpoint := saturatedLoopback(t)
	t.Run("cancel-pending-connect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		observed := &dialObserverContext{Context: ctx}
		finished := make(chan error, 1)
		go func() {
			conn, err := connectNumeric(observed, endpoint, time.Now().Add(time.Second))
			if conn != nil {
				_ = conn.Close()
			}
			finished <- err
		}()
		select {
		case err := <-finished:
			t.Fatal("full accept queue did not retain connect", err)
		case <-time.After(10 * time.Millisecond):
		}
		cancel()
		select {
		case err := <-finished:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("numeric connect failed to observe cancellation")
		}
		if observed.observers.Load() != 0 {
			t.Fatal("connect registered an unjoined cancellation observer", observed.observers.Load())
		}
	})
	t.Run("deadline-pending-connect", func(t *testing.T) {
		observed := &dialObserverContext{Context: context.Background()}
		conn, err := connectNumeric(observed, endpoint, time.Now().Add(25*time.Millisecond))
		if conn != nil {
			_ = conn.Close()
			t.Fatal("expired connection returned a socket")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if observed.observers.Load() != 0 {
			t.Fatal("deadline registered an unjoined cancellation observer")
		}
	})
	t.Run("factory-pins-pending-connect", func(t *testing.T) {
		o := testOptions()
		charge, _ := Charge(o)
		root, ref, environment := reservations(t, charge)
		before := root.Snapshot().Charged
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan error, 1)
		go func() {
			m, err := Dial(ctx, DialConfig{URL: "ws://" + endpoint.String() + "/flowersec/v4/local", RemoteAddress: endpoint, Subprotocol: SubprotocolLocal,
				CheckPolicy: func(u *url.URL, remote netip.AddrPort, _ http.Header) error {
					if remote != endpoint || u.Host != endpoint.String() {
						return ErrEndpoint
					}
					return nil
				}}, o, ref, environment)
			if m != nil {
				_ = m.Close()
				_ = m.WaitCleanup(context.Background())
				_ = m.Retire()
			}
			finished <- err
		}()
		select {
		case err := <-finished:
			t.Fatal("pending numeric prepare ended before cancellation", err)
		case <-time.After(10 * time.Millisecond):
		}
		if root.Snapshot().Charged != before {
			t.Fatal("pending connect lost provider reservation")
		}
		cancel()
		select {
		case err := <-finished:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("factory did not join numeric connect")
		}
		after := root.Snapshot().Charged
		for i := range before {
			if before[i]-after[i] != charge[i] {
				t.Fatalf("failed numeric prepare retained dimension %d", i)
			}
		}
	})
}

func TestNumericConnectOriginalSocketFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := connectNumeric(context.Background(), address, time.Now().Add(time.Second))
	if conn != nil {
		_ = conn.Close()
		t.Fatal("closed endpoint unexpectedly connected")
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("lost original socket failure: %v", err)
	}
}

func TestNumericConnectIPv6AndSynchronousHandoff(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &dialObserverContext{Context: ctx}
	conn, err := connectNumeric(observed, address, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cancel()
	if _, err := conn.Write([]byte{7}); err != nil {
		t.Fatal("completed dial retained caller cancellation", err)
	}
	var got [1]byte
	if _, err := peer.Read(got[:]); err != nil || got[0] != 7 {
		t.Fatal(got, err)
	}
	if observed.observers.Load() != 0 {
		t.Fatal("successful handoff retained context observer")
	}
}
