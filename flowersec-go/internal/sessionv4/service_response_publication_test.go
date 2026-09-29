package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func restartFlushContract(t *testing.T) []byte {
	t.Helper()
	wire, err := protocolv4.EncodeMap(make([]byte, 1024), "ServiceContract", []protocolv4.Field{
		{Name: "service_namespace", Kind: protocolv4.TextString, Text: "restart.test"}, {Name: "type_id", Number: 7}, {Name: "call_shape"}, {Name: "unary_semantics"},
		{Name: "request_schema_revision", Kind: protocolv4.TextString, Text: "restart-1"}, {Name: "response_schema_revision", Kind: protocolv4.TextString, Text: "restart-1"},
		{Name: "response_limit_mode"}, {Name: "min_response_limit_bytes", Number: 1024}, {Name: "max_response_bytes", Number: 1024}, {Name: "max_message_lifetime_ms", Number: 1000},
		{Name: "max_transient_run_ms", Number: 1000}, {Name: "restart_flush", Kind: protocolv4.Boolean, Number: 1}, {Name: "restart_flush_deadline_ms", Number: 100},
		{Name: "request_max_bytes", Number: 1024}, {Name: "application_error_catalog", Kind: protocolv4.EncodedArray, Bytes: []byte{0x80}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestResponsePublicationPreparedBeforeHandlerAndActualFlush(t *testing.T) {
	view := make(chan *ResponsePublication, 1)
	maintenance := make(chan *MaintenanceOwner, 1)
	f := newServiceDispatchFixtureContract(t, func(ctx context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
		p := r.ResponsePublication()
		if p == nil || p.Progress().Terminal || p != r.ResponsePublication() {
			t.Error("missing stable pending publication")
		}
		owner, err := r.MaintenanceOwner()
		if err != nil {
			return 0, err
		}
		if err := p.TransferTo(owner); err != nil {
			return 0, err
		}
		if err := p.TransferTo(owner); !errors.Is(err, ErrPublicationAlreadyTransferred) {
			t.Error("duplicate transfer", err)
		}
		view <- p
		maintenance <- owner
		_, err = w.Write([]byte("restart accepted"))
		return 0, err
	}, false, ApplicationShort, false, "restart_flush")
	f.request(t, nil, 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	p := <-view
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if progress, err := p.Wait(ctx); !errors.Is(err, context.Canceled) || progress.Terminal {
		t.Fatal(progress, err)
	}
	_, body := f.response(t)
	if string(body) != "restart accepted" {
		t.Fatal(string(body))
	}
	progress, err := p.Wait(resultTestContext(t))
	if err != nil || !progress.Flushed || !progress.Terminal {
		t.Fatal(progress, err)
	}
	(<-maintenance).Close()
	if !p.Progress().Flushed {
		t.Fatal("maintenance close rewrote actual publication")
	}
}

func TestResponsePublicationDeadlineAndOwnerCloseKeepProviderTail(t *testing.T) {
	view := make(chan *ResponsePublication, 1)
	owner := make(chan *MaintenanceOwner, 1)
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, r UnaryRequest, w *UnaryResponse) (uint32, error) {
		p := r.ResponsePublication()
		m, err := r.MaintenanceOwner()
		if err != nil {
			return 0, err
		}
		if err := p.TransferTo(m); err != nil {
			return 0, err
		}
		view <- p
		owner <- m
		_, err = w.Write([]byte("response"))
		return 0, err
	}, false, ApplicationShort, false, "restart_flush")
	f.request(t, nil, 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	p := <-view
	m := <-owner
	until := time.Now().Add(time.Second)
	for !p.Progress().MessageAccepted {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(until) {
			t.Fatal("response did not reach pending provider")
		}
		runtime.Gosched()
	}
	f.sink.held.Store(true)
	before := f.f.root.Snapshot().Charged
	m.Close()
	if p.Progress().Terminal {
		t.Fatal("maintenance close ended publication")
	}
	if _, err := p.Wait(context.Background()); !errors.Is(err, ErrPublicationOwnerUnavailable) {
		t.Fatal(err)
	}
	f.trust.tick.Add(101)
	f.dispatch.Advance()
	progress := p.Progress()
	if !progress.Terminal || progress.Flushed || progress.Reason != "deadline" {
		t.Fatal(progress)
	}
	if f.f.root.Snapshot().Charged != before {
		t.Fatal("deadline refunded actual provider tail")
	}
	f.sink.held.Store(false)
	if _, err := f.publisher.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.dispatch.Advance()
	if p.Progress().Flushed {
		t.Fatal("late publication changed deadline decision")
	}
}

func TestResponsePublicationFailureNeverFlushesReplacement(t *testing.T) {
	view := make(chan *ResponsePublication, 1)
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, r UnaryRequest, _ *UnaryResponse) (uint32, error) {
		view <- r.ResponsePublication()
		return 0, errors.New("handler failed")
	}, false, ApplicationShort, false, "restart_flush")
	f.request(t, nil, 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	p := <-view
	header, _ := f.response(t)
	if !header.IsSDKError() {
		t.Fatal("missing refusal")
	}
	if progress := p.Progress(); !progress.Terminal || progress.Flushed || progress.Reason != "response_superseded" {
		t.Fatal(progress)
	}
}

func TestResponsePublicationStopBeforeHandlerReturnSelectsUnknown(t *testing.T) {
	view := make(chan *ResponsePublication, 1)
	release := make(chan struct{})
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, r UnaryRequest, _ *UnaryResponse) (uint32, error) {
		view <- r.ResponsePublication()
		<-release
		return 0, nil
	}, false, ApplicationShort, false, "restart_flush")
	f.request(t, nil, 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		close(release)
		t.Fatal(err)
	}
	p := <-view
	var encoded [32]byte
	n, err := protocolv4.EncodeRPCFragment(encoded[:], protocolv4.RPCFragment{Kind: protocolv4.RPCStopOutput, Serial: f.serial})
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	if _, err := f.receiver.Feed(encoded[:n]); err != nil {
		close(release)
		t.Fatal(err)
	}
	progress := p.Progress()
	if !progress.Terminal || progress.Flushed || progress.Reason != "response_superseded" {
		close(release)
		t.Fatal(progress)
	}
	close(release)
	header, _ := f.response(t)
	if !header.IsSDKError() || p.Progress().Flushed {
		t.Fatal("replacement flushed original response")
	}
}

func TestResponsePublicationPublisherCloseEndsOriginalPendingDecision(t *testing.T) {
	view := make(chan *ResponsePublication, 1)
	release := make(chan struct{})
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, r UnaryRequest, _ *UnaryResponse) (uint32, error) {
		view <- r.ResponsePublication()
		<-release
		return 0, nil
	}, false, ApplicationShort, false, "restart_flush")
	f.request(t, nil, 0, 2000)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		close(release)
		t.Fatal(err)
	}
	p := <-view
	f.publisher.Close()
	progress, err := p.Wait(resultTestContext(t))
	if err != nil || !progress.Terminal || progress.Flushed || progress.Reason != "owner_unavailable" {
		close(release)
		t.Fatal(progress, err)
	}
	f.dispatch.Close()
	if _, err := p.Wait(context.Background()); !errors.Is(err, ErrPublicationOwnerUnavailable) {
		close(release)
		t.Fatal(err)
	}
	close(release)
}
