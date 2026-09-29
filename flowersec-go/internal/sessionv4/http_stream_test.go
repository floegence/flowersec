package sessionv4

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func httpFixture(t *testing.T, ctx context.Context, handler http.Handler, cleanupMS uint64) (*serviceFixture, *serviceTestWriter, *StreamFlow, OpenHandle, *HTTPStream) {
	t.Helper()
	options := HTTPStreamOptions{Connection: StreamConnOptions{FinishTimeoutMS: 10000, CleanupTimeoutMS: cleanupMS, RuntimeBytes: 32768},
		RuntimeBytes: 32768, ExternalRuntime: resourcev4.Vector{resourcev4.ProviderBytes: 1 << 20, resourcev4.Tasks: 3, resourcev4.WorkSlots: 1}}
	httpCharge, err := HTTPStreamCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	connCharge, _ := StreamConnCharge(options.Connection)
	dependencyCharge := resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1}
	extra := []resourcev4.Vector{StreamOwnershipCharge(), connCharge, httpCharge, dependencyCharge, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, 64, 2, testAuthorization{}, true, extra)
	writer := &serviceTestWriter{frames: make(chan []byte, 16)}
	_, peer := f.open(t, BusinessStream, 64, writer)
	handle := OpenHandle{f.local.admission, f.flows[0].receive.scope}
	o := ownFixtureStream(t, f, handle, f.reserve(t, StreamOwnershipCharge()))
	dependencies := f.reserve(t, dependencyCharge)
	t.Cleanup(dependencies.Release)
	options.Connection.HardDeadline = streamTestDeadline(t, f.local.engine)
	httpRef, connRef := f.reserve(t, httpCharge), f.reserve(t, connCharge)
	t.Cleanup(httpRef.Release)
	t.Cleanup(connRef.Release)
	h, err := StartHTTPStream(ctx, o, handler, options, httpRef, connRef, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.Abort()
		f.local.admission.Close()
		f.local.pool.Close()
		select {
		case <-h.conn.done:
		case <-time.After(4 * time.Second):
			t.Error("HTTP service retained actual resources")
		}
	})
	runWriteService(t, f)
	return f, writer, peer, handle, h
}

func httpPeerCredit(t *testing.T, f *serviceFixture, peer *StreamFlow, n int) {
	t.Helper()
	peer.receive.pool.mu.Lock()
	limit := peer.receive.limit + uint64(n)
	peer.receive.pool.mu.Unlock()
	if err := peer.receive.Grant(limit); err != nil {
		t.Fatal(err)
	}
	var raw [192]byte
	wire, err := peer.receive.encodeCredit(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.maintenance.Write(context.Background(), protocolv4.FrameStreamAck, wire); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	f.peer.control.Reset()
}

// The real record engine authenticates every native HTTP response fragment.
// The test peer supplies exact authenticated credit to this 64-byte fixture.
func httpResponse(t *testing.T, f *serviceFixture, writer *serviceTestWriter, peer *StreamFlow, untilFIN bool) []byte {
	t.Helper()
	var output []byte
	for {
		r, err := f.peer.receiver.Receive(context.Background(), nextServiceFrame(t, writer))
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := r.Body()
		fin, _ := frame.Field("fin").Bool()
		err = peer.Apply(r)
		r.Release()
		if err != nil {
			t.Fatal(err)
		}
		var chunk [64]byte
		n, _, err := peer.receive.TryRead(chunk[:])
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, chunk[:n]...)
		if len(output) > 4096 {
			t.Fatal("unexpected native HTTP output size")
		}
		if !fin {
			httpPeerCredit(t, f, peer, n)
		}
		if untilFIN && fin || !untilFIN && bytes.Contains(output, []byte("\r\n\r\n")) {
			return output
		}
		if fin {
			t.Fatal("unexpected HTTP termination")
		}
	}
}

func finishHTTP(t *testing.T, f *serviceFixture, handle OpenHandle, h *HTTPStream) protocolv4.V4CloseResult {
	t.Helper()
	if _, err := f.local.admission.PublishDrained(context.Background(), handle, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	connPeerDrained(t, f, handle)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := h.WaitCleanup(ctx)
	if err != nil || !r.SendDrained || r.ReadTerminal != protocolv4.V4ReadTerminalEof || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(r, err)
	}
	return r
}

func TestHTTPStreamFinalFlushWaitsForRealFinishAndCleanup(t *testing.T) {
	f, writer, peer, handle, h := httpFixture(t, context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Error(r.URL.Path)
		}
		_, _ = io.WriteString(w, "hello")
	}), 5000)
	deliverOwnedInput(t, f, peer, "GET / HTTP/1.0\r\n\r\n", true)
	wire := httpResponse(t, f, writer, peer, true)
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire)), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil || r.StatusCode != 200 || string(body) != "hello" {
		t.Fatal(r.StatusCode, string(body), err)
	}
	<-h.serveDone
	result, accepted, err := h.Result()
	if err != nil || accepted != uint64(len(wire)) || result.SendDrained || result.CleanupStatus.Status == protocolv4.V4CleanupStateComplete {
		t.Fatal("native server return invented Finish", result, accepted, err)
	}
	h.conn.mu.Lock()
	retained := h.external.backing.CheckRetained() == nil && h.external.dependencies.CheckRetained() == nil
	h.conn.mu.Unlock()
	if !retained {
		t.Fatal("HTTP/provider backing left before the transport tail")
	}
	finishHTTP(t, f, handle, h)
}

func TestHTTPStreamKeepAliveSurvivesNativeBackgroundReadInterruption(t *testing.T) {
	var calls atomic.Uint32
	f, writer, peer, handle, h := httpFixture(t, context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}), 5000)
	deliverOwnedInput(t, f, peer, "GET /1 HTTP/1.1\r\nHost:x\r\n\r\n", false)
	first := httpResponse(t, f, writer, peer, false)
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(first)), nil)
	if err != nil || r.StatusCode != http.StatusNoContent {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	deliverOwnedInput(t, f, peer, "GET /2 HTTP/1.0\r\n\r\n", true)
	second := httpResponse(t, f, writer, peer, true)
	r, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(second)), nil)
	if err != nil || r.StatusCode != http.StatusNoContent || calls.Load() != 2 {
		t.Fatal(err, calls.Load())
	}
	_ = r.Body.Close()
	finishHTTP(t, f, handle, h)
}

func TestHTTPStreamHijackRetainsOriginalCancellationOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hijacked := make(chan net.Conn, 1)
	f, _, peer, _, h := httpFixture(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		hijacked <- conn
	}), 5000)
	deliverOwnedInput(t, f, peer, "GET / HTTP/1.1\r\nHost:x\r\n\r\n", false)
	var conn net.Conn
	select {
	case conn = <-hijacked:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not hijack")
	}
	read := make(chan error, 1)
	go func() { var b [1]byte; _, err := conn.Read(b[:]); read <- err }()
	waitReadAdmitted(t, f.flows[0].receive)
	cancel()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("canceled hijacked read succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hijack escaped original cancellation")
	}
	select {
	case <-h.serveDone:
	case <-time.After(3 * time.Second):
		t.Fatal("hijacked HTTP service retained native dispatch")
	}
	result, _, err := h.Result()
	if err == nil || result.SendDrained {
		t.Fatal("cancellation became normal completion", result, err)
	}
}

func TestHTTPStreamBlockedHandlerKeepsExternalResponsibilityAfterTransportExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f, _, peer, _, h := httpFixture(t, ctx, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }), 40)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	deliverOwnedInput(t, f, peer, "GET / HTTP/1.0\r\n\r\n", true)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP handler did not enter")
	}
	cancel()
	f.local.admission.Close()
	f.local.pool.Close()
	wait, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	r, err := h.WaitCleanup(wait)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || r.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete || r.CleanupStatus.PendingCallbacks != 1 {
		t.Fatal(r, err)
	}
	h.conn.mu.Lock()
	retained := h.external.backing.CheckRetained() == nil && h.external.dependencies.CheckRetained() == nil
	h.conn.mu.Unlock()
	if !retained {
		t.Fatal("blocked handler lost its native/input backing")
	}
	once.Do(func() { close(release) })
	select {
	case <-h.conn.done:
	case <-wait.Done():
		t.Fatal("handler exit did not finish compound cleanup")
	}
	if h.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(h.CleanupStatus())
	}
}

type httpPanicReason struct{ formatted *atomic.Bool }

func (p httpPanicReason) String() string { p.formatted.Store(true); return "private panic" }

func TestHTTPStreamHandlerPanicUsesFixedAbortAndNoFormatting(t *testing.T) {
	var formatted atomic.Bool
	f, _, peer, _, h := httpFixture(t, context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(httpPanicReason{&formatted}) }), 5000)
	deliverOwnedInput(t, f, peer, "GET / HTTP/1.0\r\n\r\n", true)
	select {
	case <-h.conn.closeStart:
	case <-time.After(3 * time.Second):
		t.Fatal("handler panic did not abort")
	}
	_, _, err := h.Result()
	if !errors.Is(err, ErrHTTPHandlerExit) || formatted.Load() {
		t.Fatal(err, formatted.Load())
	}
}

func TestHTTPStreamCompletedCompoundCleanupWinsLateCancellation(t *testing.T) {
	release := make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	f, writer, peer, handle, h := httpFixture(t, context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = conn.Write([]byte("upgraded tail"))
		_ = conn.Close()
		<-release
	}), 5000)
	// A fixture cleanup participant keeps compound publication pending while
	// the real HTTP workers exit. Native listener Close also needs conn.mu,
	// so holding that mutex while waiting for those workers would deadlock.
	h.mu.Lock()
	h.workers++
	h.mu.Unlock()
	completeExternal := sync.OnceFunc(h.exitWorker)
	t.Cleanup(completeExternal)
	deliverOwnedInput(t, f, peer, "GET / HTTP/1.1\r\nHost:x\r\n\r\n", true)
	if wire := httpResponse(t, f, writer, peer, true); string(wire) != "upgraded tail" {
		t.Fatal(string(wire))
	}
	if _, err := f.local.admission.PublishDrained(context.Background(), handle, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	connPeerDrained(t, f, handle)
	select {
	case <-h.conn.workerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("transport did not actually retire")
	}
	stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		h.mu.Lock()
		workers := h.workers
		h.mu.Unlock()
		if workers == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("HTTP workers did not actually exit")
		}
		runtime.Gosched()
	}
	// Hold publication so this cancellation races actual completion, not an
	// already published result. No active external or transport work remains.
	h.conn.mu.Lock()
	completeExternal()
	h.conn.closeLocked(context.Canceled)
	h.conn.mu.Unlock()
	r, err := h.WaitCleanup(ctx)
	if err != nil || !r.SendDrained || r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal("late cancellation overwrote actual completion", r, err)
	}
}
