package sessionv4

import (
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type facadeHeldReader struct {
	entered, release chan struct{}
}

func (r *facadeHeldReader) Read(p []byte) (int, error) {
	close(r.entered)
	<-r.release
	return copy(p, "tail"), io.EOF
}

func TestRawFacadeCloseRetainsActualCopyTailThenReleasesOwner(t *testing.T) {
	cores, fixtures, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	streams := factoryOpenPair(t, cores, ctx)
	o := streams[0]
	before := fixtures[0].root.Snapshot()
	r := &facadeHeldReader{make(chan struct{}), make(chan struct{})}
	done := make(chan struct{})
	var result CopyResult
	var copyErr error
	go func() {
		result, copyErr = o.CopyFromReader(ctx, r, 4)
		close(done)
	}()
	select {
	case <-r.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal("repeat Close", err)
	}
	o.mu.Lock()
	retained := o.admission != nil && o.users != 0
	o.mu.Unlock()
	after := fixtures[0].root.Snapshot()
	if !retained || after.Charged[resourcev4.SDKBytes] < before.Charged[resourcev4.SDKBytes]+4 {
		t.Error("Close released actual synchronous reader responsibility", retained, before, after)
	}
	close(r.release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if copyErr == nil || result.Progress.SourceReadBytes != 4 || result.Progress.DestinationAcceptedBytes != 0 || string(result.Progress.UnacceptedTail) != "tail" {
		t.Fatal("Close erased the read tail or accepted after revocation", result, copyErr)
	}
	until := time.Now().Add(time.Second)
	for {
		o.mu.Lock()
		detached := o.admission == nil
		o.mu.Unlock()
		if detached {
			break
		}
		if time.Now().After(until) {
			t.Fatal("original coordinator retained the closed raw owner")
		}
		runtime.Gosched()
	}
	if _, err := o.CloseResult(); err != nil {
		t.Fatal("Close lost its compact observation", err)
	}
}

func TestFacadeCopyFromStreamRetainsOriginalReadPosition(t *testing.T) {
	cores, _, ctx := factoryCorePair(t, "stream", factoryStreamConfig())
	source := factoryOpenPair(t, cores, ctx)
	target := factoryOpenPair(t, cores, ctx)
	done := make(chan struct{})
	var result CopyResult
	var copyErr error
	go func() {
		result, copyErr = target[0].CopyFromStream(ctx, source[0], 4)
		close(done)
	}()
	if _, err := source[1].WriteAll(ctx, []byte("data")); err != nil {
		t.Fatal(err)
	}
	var data [4]byte
	if r, err := target[1].ReadInto(ctx, data[:]); err != nil || r.Progress.Filled != 4 || string(data[:]) != "data" {
		t.Fatal(r, err, string(data[:]))
	}
	if _, err := source[0].ReadInto(ctx, data[:]); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("Copy yielded its original read claim between chunks", err)
	}
	if err := source[1].CloseWrite(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if copyErr != nil || result.Progress.SourceReadBytes != 4 || result.Progress.DestinationAcceptedBytes != 4 || len(result.Progress.UnacceptedTail) != 0 {
		t.Fatal(result, copyErr)
	}
}

func TestFacadeCopyAdmissionFailureDoesNotEnterReader(t *testing.T) {
	f, _, _, h, ref := ownedFixture(t, 64)
	o := ownFixtureStream(t, f, h, ref)
	reader := &facadeHeldReader{make(chan struct{}), make(chan struct{})}
	// This low-level owner has no factory allocation root. It must fail before
	// calling external code instead of allocating an uncharged fallback chunk.
	if _, err := o.CopyFromReader(context.Background(), reader, 4); err == nil {
		t.Fatal("missing original budget accepted a copy")
	}
	select {
	case <-reader.entered:
		t.Fatal("reader entered before copy admission")
	default:
	}
}
