package sessionv4

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type nativeDialFixture struct {
	root         *resourcev4.Root
	clock        *timev4.Clock
	options      NativeTCPDialOptions
	dial, socket resourcev4.Reference
	account      resourcev4.Account
}

func newNativeDialFixture(t *testing.T) *nativeDialFixture {
	t.Helper()
	f := &nativeDialFixture{clock: sessionTestClock(t)}
	hard, err := timev4.NewAge(f.clock, 60000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	f.options = NativeTCPDialOptions{TimeoutMS: 3000, CleanupTimeoutMS: 30, RuntimeBytes: 256 * 1024, HardDeadline: hard, Endpoint: NativeTCPOptions{RuntimeBytes: 64 * 1024, ProviderBytes: 256 * 1024}}
	dial, _ := NativeTCPDialCharge(f.options)
	socket, _ := NativeTCPCharge(f.options.Endpoint)
	limit, err := dial.Add(socket)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 2, ReservationSlots: 2, ReferenceSlots: 12, Limit: limit}
	backing, _ := resourcev4.BackingBytes(config)
	config.Limit[resourcev4.SDKBytes] += backing
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.root.Close()
		if !f.root.Snapshot().CleanupComplete {
			t.Error("native factory retained actual resources", f.root.Snapshot())
		}
	})
	f.account, err = f.root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{1}}, socket)
	if err != nil {
		t.Fatal(err)
	}
	key := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	f.dial, err = f.root.Reserve(key, dial)
	if err != nil {
		t.Fatal(err)
	}
	key.Instance[0], key.Backing[0] = 2, 2
	f.socket, err = f.root.Reserve(key, socket, f.account)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.dial.Release)
	t.Cleanup(f.socket.Release)
	return f
}

func waitNativeDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("native owner did not exit")
	}
}

func nativeWait(t *testing.T, d *NativeTCPDial) (*NativeTCP, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return d.Wait(ctx)
}

func nativeListener(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	return listener
}

func nativePair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener := nativeListener(t)
	conn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	return conn, peer
}

// Tests drive the private preparation/settlement gates directly. Production
// still has exactly one concrete dialer, with no application provider hook.
func (f *nativeDialFixture) prepare(t *testing.T, ctx context.Context) (*NativeTCPDial, resourcev4.Reference, resourcev4.Reference) {
	t.Helper()
	d, worker, socket, supervisor, err := prepareNativeTCPDial(ctx, f.clock, netip.MustParseAddrPort("127.0.0.1:12345"), f.options, f.dial, f.socket)
	if err != nil {
		t.Fatal(err)
	}
	go d.supervise(supervisor)
	return d, worker, socket
}

func settleNative(d *NativeTCPDial, worker, socket resourcev4.Reference, conn *net.TCPConn, err error) {
	d.settle(conn, err)
	socket.Release()
	worker.Release()
	close(d.providerDone)
}

func TestNativeTCPDialRealLoopbackHandoffOwnsOriginalConnection(t *testing.T) {
	f := newNativeDialFixture(t)
	listener := nativeListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := StartNativeTCPDial(ctx, f.clock, listener.Addr().(*net.TCPAddr).AddrPort(), f.options, f.dial, f.socket)
	if err != nil {
		t.Fatal(err)
	}
	n, err := nativeWait(t, d)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	waitNativeDone(t, d.Done())
	cancel()
	d.Cancel()
	again, err := nativeWait(t, d)
	if err != nil || again != n || n.clock != f.clock {
		t.Fatal("delivered owner changed", again, err)
	}
	if _, err := n.conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var dst [5]byte
	if _, err := io.ReadFull(peer, dst[:]); err != nil || string(dst[:]) != "hello" {
		t.Fatal(string(dst[:]), err)
	}
	f.dial.Release()
	f.socket.Release()
	snapshot := f.root.Snapshot()
	if snapshot.Reservations != 1 || snapshot.Charged[resourcev4.NativeHandles] != 1 || snapshot.Charged[resourcev4.Tasks] != 0 {
		t.Fatal("handoff lost socket or retained provider", snapshot)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			err := n.Close()
			if err != nil && !errors.Is(err, ErrNativeTCPClosing) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	waitNativeDone(t, n.Done())
	if n.CleanupStatus().Status != protocolv4.V4CleanupStateComplete || f.root.Snapshot().Reservations != 0 {
		t.Fatal("close did not release actual endpoint")
	}
}

func TestNativeTCPDialCanceledWaitDoesNotCancelAndWaiterIsBounded(t *testing.T) {
	f := newNativeDialFixture(t)
	d, worker, socket := f.prepare(t, context.Background())
	defer func() {
		d.Cancel()
		settleNative(d, worker, socket, nil, ErrNativeTCPDial)
		waitNativeDone(t, d.Done())
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := d.Wait(ctx); result <- err }()
	end := time.Now().Add(3 * time.Second)
	for {
		d.mu.Lock()
		waiting := d.waiting
		d.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(end) {
			t.Fatal("waiter never registered")
		}
		runtime.Gosched()
	}
	if _, err := d.Wait(context.Background()); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("unbounded observer", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := d.admitProvider(); err != nil {
		t.Fatal("wait cancellation revoked operation", err)
	}
}

func TestNativeTCPDialLateSuccessRetainsChargesUntilRealProviderExit(t *testing.T) {
	for _, cause := range []string{"cancel", "deadline"} {
		t.Run(cause, func(t *testing.T) {
			f := newNativeDialFixture(t)
			if cause == "deadline" {
				f.options.TimeoutMS = 25
			}
			d, worker, socket := f.prepare(t, context.Background())
			if err := d.admitProvider(); err != nil {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			if cause == "cancel" {
				d.Cancel()
			}
			n, err := nativeWait(t, d)
			expected := error(ErrNativeTCPDialCanceled)
			if cause == "deadline" {
				expected = timev4.ErrExpired
			}
			if n != nil || !errors.Is(err, expected) {
				t.Fatal("late operation became successful", n, err)
			}
			if d.CleanupStatus().Status != protocolv4.V4CleanupStateCleanupIncomplete {
				t.Fatal("physical work reported complete")
			}
			after := f.root.Snapshot()
			if after.Charged != before.Charged || after.Reservations != 2 {
				t.Fatal("logical timeout refunded real native tail", before, after)
			}
			conn, peer := nativePair(t)
			settleNative(d, worker, socket, conn, nil)
			waitNativeDone(t, d.Done())
			var b [1]byte
			if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
				t.Fatal("late native connection remained live", err)
			}
			if n, err := nativeWait(t, d); n != nil || !errors.Is(err, expected) {
				t.Fatal("late completion replaced first cause", n, err)
			}
			if d.CleanupStatus().Status != protocolv4.V4CleanupStateComplete || f.root.Snapshot().Reservations != 0 {
				t.Fatal("actual late exit not refunded")
			}
		})
	}
}

func TestNativeTCPDialOriginalGatesRejectClosedSocketAccount(t *testing.T) {
	for _, phase := range []string{"invoke", "settle", "deliver"} {
		t.Run(phase, func(t *testing.T) {
			f := newNativeDialFixture(t)
			d, worker, socket := f.prepare(t, context.Background())
			if phase != "invoke" {
				if err := d.admitProvider(); err != nil {
					t.Fatal(err)
				}
			}
			var conn, peer *net.TCPConn
			if phase != "invoke" {
				conn, peer = nativePair(t)
			}
			if phase == "deliver" {
				go settleNative(d, worker, socket, conn, nil)
				waitNativeDone(t, d.ready)
			}
			f.account.Close()
			if phase == "invoke" && !errors.Is(d.admitProvider(), resourcev4.ErrClosed) {
				t.Fatal("provider invoked after original socket scope closed")
			}
			if phase != "deliver" {
				go settleNative(d, worker, socket, conn, nil)
			}
			if n, err := nativeWait(t, d); n != nil || !errors.Is(err, resourcev4.ErrClosed) {
				t.Fatal("closed original socket scope delivered", n, err)
			}
			waitNativeDone(t, d.Done())
			if peer != nil {
				var b [1]byte
				if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
					t.Fatal("rejected candidate not closed", err)
				}
			}
		})
	}
}

func TestNativeTCPDialCandidateExpiresWithoutObserver(t *testing.T) {
	f := newNativeDialFixture(t)
	f.options.TimeoutMS = 60
	d, worker, socket := f.prepare(t, context.Background())
	conn, peer := nativePair(t)
	go settleNative(d, worker, socket, conn, nil)
	waitNativeDone(t, d.ready)
	waitNativeDone(t, d.Done())
	if n, err := nativeWait(t, d); n != nil || !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("unclaimed connection escaped original deadline", n, err)
	}
	var b [1]byte
	if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestNativeTCPDialOriginalCancellationAtInvocationAndDelivery(t *testing.T) {
	for _, phase := range []string{"invoke", "deliver"} {
		t.Run(phase, func(t *testing.T) {
			f := newNativeDialFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, worker, socket := f.prepare(t, ctx)
			if phase == "deliver" {
				conn, _ := nativePair(t)
				go settleNative(d, worker, socket, conn, nil)
				waitNativeDone(t, d.ready)
			}
			cancel()
			if phase == "invoke" {
				if err := d.admitProvider(); !errors.Is(err, context.Canceled) {
					t.Fatal("provider entered after original cancel", err)
				}
				go settleNative(d, worker, socket, nil, context.Canceled)
			}
			if n, err := nativeWait(t, d); n != nil || !errors.Is(err, context.Canceled) {
				t.Fatal("canceled original operation delivered", n, err)
			}
			waitNativeDone(t, d.Done())
		})
	}
}

func TestNativeTCPDialRejectsInvalidConfigurationBeforeTakingResources(t *testing.T) {
	for _, address := range []string{"0.0.0.0:80", "[::]:80", "127.0.0.1:0", "224.0.0.1:80", "[::ffff:127.0.0.1]:80", "[fe80::1%en0]:80"} {
		t.Run(address, func(t *testing.T) {
			f := newNativeDialFixture(t)
			if _, err := StartNativeTCPDial(context.Background(), f.clock, netip.MustParseAddrPort(address), f.options, f.dial, f.socket); !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal(err)
			}
			if f.dial.Check() != nil || f.socket.Check() != nil {
				t.Fatal("invalid configuration took original reservations")
			}
		})
	}
	f := newNativeDialFixture(t)
	other := newNativeDialFixture(t)
	addr := netip.MustParseAddrPort("127.0.0.1:12345")
	if _, err := StartNativeTCPDial(context.Background(), other.clock, addr, f.options, f.dial, f.socket); !errors.Is(err, timev4.ErrOwner) {
		t.Fatal("foreign clock", err)
	}
	if _, err := StartNativeTCPDial(context.Background(), f.clock, addr, f.options, f.dial, other.socket); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("foreign root", err)
	}
	if _, err := StartNativeTCPDial(context.Background(), f.clock, addr, f.options, f.dial, f.dial); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("aliased charges", err)
	}
}

func TestNativeTCPDialFirstFailureOwnsCleanupDeadline(t *testing.T) {
	f := newNativeDialFixture(t)
	d, worker, socket, supervisor, err := prepareNativeTCPDial(context.Background(), f.clock, netip.MustParseAddrPort("127.0.0.1:12345"), f.options, f.dial, f.socket)
	if err != nil {
		t.Fatal(err)
	}
	d.Cancel()
	d.mu.Lock()
	original := d.cleanup
	d.mu.Unlock()
	if original == nil {
		t.Fatal("first failure did not acquire original cleanup deadline")
	}
	// Delay only the supervisor; the real operation already failed.
	timer := time.NewTimer(2 * time.Duration(f.options.CleanupTimeoutMS) * time.Millisecond)
	<-timer.C
	d.Cancel()
	d.mu.Lock()
	same := d.cleanup == original
	d.mu.Unlock()
	if !same {
		t.Fatal("repeat Cancel renewed cleanup deadline")
	}
	go d.supervise(supervisor)
	if n, err := nativeWait(t, d); n != nil || !errors.Is(err, ErrNativeTCPDialCanceled) {
		t.Fatal(n, err)
	}
	if d.CleanupStatus().Status != protocolv4.V4CleanupStateCleanupIncomplete {
		t.Fatal("delayed supervisor replaced expired cleanup deadline")
	}
	settleNative(d, worker, socket, nil, ErrNativeTCPDial)
	waitNativeDone(t, d.Done())
}

// Blocking this observer's Done lookup models a descheduled admitted waiter;
// it cannot block the factory's independent original context or supervisor.
type nativePausedObserver struct {
	context.Context
	entered, release chan struct{}
}

func (c *nativePausedObserver) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return nil
}

func TestNativeTCPDialCleanupIncludesAdmittedObserverTail(t *testing.T) {
	f := newNativeDialFixture(t)
	d, worker, socket := f.prepare(t, context.Background())
	ctx := &nativePausedObserver{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	observed := make(chan error, 1)
	go func() { _, err := d.Wait(ctx); observed <- err }()
	waitNativeDone(t, ctx.entered)
	d.Cancel()
	settleNative(d, worker, socket, nil, ErrNativeTCPDial)
	end := time.Now().Add(3 * time.Second)
	for {
		d.mu.Lock()
		exited := d.complete
		d.mu.Unlock()
		if exited {
			break
		}
		if time.Now().After(end) {
			close(ctx.release)
			t.Fatal("supervisor failed to exit")
		}
		runtime.Gosched()
	}
	if d.CleanupStatus().Status == protocolv4.V4CleanupStateComplete {
		t.Error("complete while admitted observer still owns original backing")
	}
	select {
	case <-d.Done():
		t.Error("Done closed before observer exit")
	default:
	}
	if f.root.Snapshot().Charged[resourcev4.Tasks] == 0 {
		t.Error("observer charge refunded early")
	}
	timer := time.NewTimer(2 * time.Duration(f.options.CleanupTimeoutMS) * time.Millisecond)
	<-timer.C
	if d.CleanupStatus().Status != protocolv4.V4CleanupStateCleanupIncomplete {
		t.Error("observer tail bypassed original cleanup deadline")
	}
	close(ctx.release)
	if err := <-observed; !errors.Is(err, ErrNativeTCPDialCanceled) {
		t.Fatal(err)
	}
	waitNativeDone(t, d.Done())
	if d.CleanupStatus().Status != protocolv4.V4CleanupStateComplete || f.root.Snapshot().Reservations != 0 {
		t.Fatal("exited observer still charged")
	}
}
