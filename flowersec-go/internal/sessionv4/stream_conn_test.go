package sessionv4

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func connFixture(t *testing.T, capacity uint64) (*serviceFixture, *SendQueue, *StreamFlow, OpenHandle, *StreamOwnership, *StreamConn) {
	t.Helper()
	options := StreamConnOptions{TimeoutMS: 20000, FinishTimeoutMS: 10000, CleanupTimeoutMS: 5000, RuntimeBytes: 32768}
	return connFixtureOptions(t, capacity, options)
}

func connFixtureOptions(t *testing.T, capacity uint64, options StreamConnOptions) (*serviceFixture, *SendQueue, *StreamFlow, OpenHandle, *StreamOwnership, *StreamConn) {
	t.Helper()
	return connFixtureContext(t, capacity, options, context.Background())
}

func connFixtureContext(t *testing.T, capacity uint64, options StreamConnOptions, ctx context.Context) (*serviceFixture, *SendQueue, *StreamFlow, OpenHandle, *StreamOwnership, *StreamConn) {
	t.Helper()
	charge, err := StreamConnCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	extra := []resourcev4.Vector{StreamOwnershipCharge(), charge, {}, {}, {}, {}, {}, {}}
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, capacity, 2, testAuthorization{}, true, extra)
	q, peer := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
	h := OpenHandle{f.local.admission, f.flows[0].receive.scope}
	o := ownFixtureStream(t, f, h, f.reserve(t, StreamOwnershipCharge()))
	options.HardDeadline = streamTestDeadline(t, f.local.engine)
	c, err := o.AsConn(ctx, options, f.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Abort()
		f.local.admission.Close()
		f.local.pool.Close()
		select {
		case <-c.done:
		case <-time.After(4 * time.Second):
			t.Error("connection retained original workers")
		}
	})
	return f, q, peer, h, o, c
}

func TestStreamConnReadDeadlinePreservesOriginalBytes(t *testing.T) {
	f, _, peer, _, o, c := connFixture(t, 64)
	if _, err := o.ReadInto(context.Background(), make([]byte, 1)); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("raw read bypassed adapter", err)
	}
	if _, err := o.Write(context.Background(), []byte("raw")); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("raw write bypassed adapter", err)
	}
	if err := o.Release(); !errors.Is(err, ErrStreamOwnershipBusy) {
		t.Fatal("raw release detached adapter", err)
	}
	buffer := []byte("unchanged")
	read := make(chan error, 1)
	go func() { _, err := c.Read(buffer); read <- err }()
	waitReadAdmitted(t, f.flows[0].receive)
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-read; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	if string(buffer) != "unchanged" {
		t.Fatal("interrupted read modified caller buffer")
	}
	deliverOwnedInput(t, f, peer, "later", true)
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(buffer)
	if n != 5 || err != io.EOF || string(buffer[:n]) != "later" {
		t.Fatal(n, err, string(buffer))
	}
	_, _, err = c.Result()
	if err != nil {
		t.Fatal("reversible read deadline became a connection failure", err)
	}
}

func TestStreamConnCloseFencesBothBuffersAndRetainsAcceptedPrefix(t *testing.T) {
	f, q, peer, _, o, c := connFixture(t, 2)
	write := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte("abcdef"))
		write <- struct {
			n   int
			err error
		}{n, err}
	}()
	waitSendQueueWriters(t, q, 1)
	buffer := []byte("same")
	read := make(chan error, 1)
	go func() { _, err := c.Read(buffer); read <- err }()
	waitReadAdmitted(t, f.flows[0].receive)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	r := <-write
	if r.n != 2 || !errors.Is(r.err, net.ErrClosed) || o.AcceptedBytes() != 2 {
		t.Fatal(r, o.AcceptedBytes())
	}
	if err := <-read; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	deliverOwnedInput(t, f, peer, "tail", true)
	if string(buffer) != "same" {
		t.Fatal("Close allowed a late caller-buffer write")
	}
	if n, err := c.Write([]byte("late")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatal(n, err)
	}
	if err := c.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	result, n, err := c.Result()
	if n != 2 || err != nil || result.SendDrained {
		t.Fatal("Close invented Finish or erased acceptance", result, n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func connDeliverSend(t *testing.T, f *serviceFixture, writer *serviceTestWriter, peer *StreamFlow) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		r, err := f.peer.receiver.Receive(ctx, nextServiceFrame(t, writer))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := r.Body()
		fin, _ := body.Field("fin").Bool()
		err = peer.Apply(r)
		r.Release()
		if err != nil {
			t.Fatal(err)
		}
		if fin {
			break
		}
	}
	var output [64]byte
	n, terminal, err := peer.receive.TryRead(output[:])
	if err != nil || terminal != protocolv4.V4ReadTerminalEof {
		t.Fatal(terminal, err)
	}
	return string(output[:n])
}

func connPeerDrained(t *testing.T, f *serviceFixture, h OpenHandle) {
	t.Helper()
	if _, err := f.peer.admission.PublishDrained(context.Background(), OpenHandle{f.peer.admission, h.scope}, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
}

func TestStreamConnCloseWaitsForAuthenticatedFinishAndPreservesHalfClose(t *testing.T) {
	f, q, peer, h, _, c := connFixture(t, 64)
	writer := q.flow.writer.writer.(*serviceTestWriter)
	runWriteService(t, f)
	if n, err := c.Write([]byte("response")); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Write([]byte("late")); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("closed sending half accepted bytes", n, err)
	}
	if got := connDeliverSend(t, f, writer, peer); got != "response" {
		t.Fatal(got)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Finish(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("local FIN was treated as remote drain", err)
	}
	// The reverse direction remains usable after CloseWrite and canceled Finish.
	deliverOwnedInput(t, f, peer, "reply", true)
	var buffer [8]byte
	if n, err := c.Read(buffer[:]); n != 5 || err != io.EOF || string(buffer[:n]) != "reply" {
		t.Fatal(n, err)
	}
	connPeerDrained(t, f, h)
	if err := c.Finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.admission.PublishDrained(context.Background(), h, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	r, err := c.WaitCleanup(ctx)
	if err != nil || !r.SendDrained || r.ReadTerminal != protocolv4.V4ReadTerminalEof || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(r, err)
	}
	if err := c.Finish(canceled); err != nil {
		t.Fatal("detached compact result lost completed Finish", err)
	}
	if n, err := c.Read(buffer[:]); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatal(n, err)
	}
}

func TestStreamConnCloseDrainsOutputThenOnlyAbandonsReceivingHalf(t *testing.T) {
	f, q, peer, h, _, c := connFixture(t, 64)
	writer := q.flow.writer.writer.(*serviceTestWriter)
	runWriteService(t, f)
	if _, err := c.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := connDeliverSend(t, f, writer, peer); got != "response" {
		t.Fatal(got)
	}
	connPeerDrained(t, f, h)
	until := time.Now().Add(3 * time.Second)
	for {
		f.flows[0].receive.pool.mu.Lock()
		abandoned := f.flows[0].receive.abandoned
		f.flows[0].receive.pool.mu.Unlock()
		if abandoned {
			break
		}
		if time.Now().After(until) {
			t.Fatal("drained sending half waited for reverse EOF")
		}
		runtime.Gosched()
	}
	f.local.admission.mu.Lock()
	s, err := f.local.admission.slot(h)
	canceled := err == nil && s.cancelled
	f.local.admission.mu.Unlock()
	if err != nil || canceled {
		t.Fatal("normal close reset successful sending half", err)
	}
	ctx := context.Background()
	if _, err := f.local.admission.PublishStop(ctx, h, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	if got := applyTerminalWire(t, f.peer, f.local.control.Bytes()); got != "STREAM_ACK_STOP" {
		t.Fatal(got)
	}
	f.local.control.Reset()
	if _, err := f.peer.admission.PublishStopped(ctx, OpenHandle{f.peer.admission, h.scope}, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
	if _, err := f.local.admission.PublishDrained(ctx, h, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := c.WaitCleanup(wait)
	if err != nil || !r.SendDrained || r.ReadTerminal != protocolv4.V4ReadTerminalAbandoned || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(r, err)
	}
}

func TestStreamConnWriteDeadlineKeepsPartialAcceptance(t *testing.T) {
	_, q, _, _, o, c := connFixture(t, 2)
	write := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte("abcdef"))
		write <- struct {
			n   int
			err error
		}{n, err}
	}()
	waitSendQueueWriters(t, q, 1)
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	r := <-write
	if r.n != 2 || !errors.Is(r.err, os.ErrDeadlineExceeded) || o.AcceptedBytes() != 2 {
		t.Fatal(r, o.AcceptedBytes())
	}
	if n, err := c.Write([]byte("retry")); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatal(n, err)
	}
	result, n, err := c.Result()
	if n != 2 || !errors.Is(err, os.ErrDeadlineExceeded) || result.SendDrained {
		t.Fatal(result, n, err)
	}
}

func TestStreamConnBlockedProviderRetainsOriginalCleanupResources(t *testing.T) {
	options := StreamConnOptions{TimeoutMS: 20000, FinishTimeoutMS: 40, CleanupTimeoutMS: 40, RuntimeBytes: 32768}
	f, q, _, _, _, c := connFixtureOptions(t, 64, options)
	writer := q.flow.writer.writer.(*serviceTestWriter)
	writer.entered, writer.release = make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(writer.release) }) })
	runWriteService(t, f)
	if _, err := c.Write([]byte("buffered")); err != nil {
		t.Fatal(err)
	}
	<-writer.entered
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := c.WaitCleanup(wait)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || r.SendDrained || r.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete {
		t.Fatal(r, err)
	}
	c.mu.Lock()
	retained := !c.complete && c.owner != nil && c.reservation.Check() == nil
	c.mu.Unlock()
	if !retained {
		t.Fatal("timeout refunded still-blocked native resources")
	}
	release.Do(func() { close(writer.release) })
	f.local.admission.Close()
	f.local.pool.Close()
	select {
	case <-c.done:
	case <-wait.Done():
		t.Fatal("actual provider exit did not complete cleanup")
	}
	if c.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(c.CleanupStatus())
	}
}

func TestStreamConnFutureWriteDeadlineAndOriginalRevocation(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		_, q, _, _, _, c := connFixture(t, 2)
		result := make(chan struct {
			n   int
			err error
		}, 1)
		go func() {
			n, err := c.Write([]byte("abcdef"))
			result <- struct {
				n   int
				err error
			}{n, err}
		}()
		waitSendQueueWriters(t, q, 1)
		if err := c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		r := <-result
		if r.n != 2 || !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Fatal("supervised write timeout lost its real cause", r)
		}
	})
	t.Run("revoke", func(t *testing.T) {
		_, _, _, _, o, c := connFixture(t, 2)
		o.Revoke()
		select {
		case <-c.closeStart:
		case <-time.After(time.Second):
			t.Fatal("idle adapter ignored original revocation")
		}
		_, _, err := c.Result()
		if !errors.Is(err, ErrStreamOwned) {
			t.Fatal(err)
		}
	})
}

func TestStreamConnFutureReadDeadlineCanBeReplaced(t *testing.T) {
	f, _, peer, _, _, c := connFixture(t, 64)
	buffer := make([]byte, 8)
	result := make(chan error, 1)
	go func() { _, err := c.Read(buffer); result <- err }()
	waitReadAdmitted(t, f.flows[0].receive)
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	deliverOwnedInput(t, f, peer, "more", false)
	if n, err := c.Read(buffer); n != 4 || err != nil || string(buffer[:n]) != "more" {
		t.Fatal(n, err)
	}
}

func TestStreamConnParentCancellationFencesActualAcceptanceBeforeSupervisor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := StreamConnOptions{TimeoutMS: 20000, FinishTimeoutMS: 10000, CleanupTimeoutMS: 5000, RuntimeBytes: 32768}
	f, q, _, _, _, c := connFixtureContext(t, 2, options, ctx)
	write := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte("abcdef"))
		write <- struct {
			n   int
			err error
		}{n, err}
	}()
	waitSendQueueWriters(t, q, 1)
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	cancel()
	// Keep the supervisor outside its gate while real provider progress frees
	// the original queue. The acceptance gate itself must check cancellation.
	runWriteService(t, f)
	until := time.Now().Add(time.Second)
	for {
		q.mu.Lock()
		pending, accepted := q.waiters, q.accepted
		q.mu.Unlock()
		if accepted != 2 {
			t.Fatal("canceled owner accepted a late suffix", accepted)
		}
		if pending == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("canceled writer did not leave original gate")
		}
		runtime.Gosched()
	}
	c.mu.Unlock()
	locked = false
	r := <-write
	if r.n != 2 || r.err == nil {
		t.Fatal(r)
	}
}
