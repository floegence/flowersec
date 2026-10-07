package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Exercise the StreamOwnership entry used by the public Stream.PrepareWrite
// facade, including its original send service, immutable slot and cleanup.
func TestOwnedWriteDiagnosticsRetireAndReuseOriginalSlots(t *testing.T) {
	const operationSlots = 2
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	diagnostics := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: operationSlots, QueueEvents: 64}, func(context.Context, diagnosticv4.Event) {}, func(uint16) bool {
		enteredOnce.Do(func() { close(entered) })
		<-release
		return true
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	// Sampling runs outside the sink gate. Hold that real pump turn so the
	// best-effort producer cannot lose events to unrelated lock contention;
	// inspect the actual bounded queue without replacing any lifecycle path.
	primer := diagnostics.begin(t)
	diagnosticEmit(t, primer, diagnosticv4.Fields{Phase: diagnosticv4.PhaseOther})
	diagnosticReceive(t, entered)
	primer.Close()
	seen := make(map[[16]byte]bool)
	for _, tc := range []struct {
		name   string
		reason protocolv4.V4WriteTerminalReason
		cause  error
		code   diagnosticv4.Code
	}{
		{name: "success", reason: protocolv4.V4WriteTerminalReasonComplete, code: diagnosticv4.CodeOK},
		{name: "cancel", reason: protocolv4.V4WriteTerminalReasonCanceled, cause: context.Canceled, code: diagnosticv4.CodeCancelled},
		{name: "deadline", reason: protocolv4.V4WriteTerminalReasonDeadlineExceeded, cause: context.DeadlineExceeded, code: diagnosticv4.CodeTimeout},
		{name: "stream_close", reason: protocolv4.V4WriteTerminalReasonStreamTerminated, cause: ErrFlowClosed, code: diagnosticv4.CodeOther},
	} {
		for iteration := 0; iteration < operationSlots+1; iteration++ {
			t.Run(fmt.Sprintf("%s/%d", tc.name, iteration), func(t *testing.T) {
				f, q, _, handle, reservation := ownedFixture(t, 64)
				owner := ownFixtureStream(t, f, handle, reservation)
				q.flow.mu.Lock()
				q.flow.limit = 0
				q.flow.diagnosticSink = diagnostics.sink
				q.flow.mu.Unlock()
				runWriteService(t, f)
				beforeAccepted := uint64(0)
				if tc.cause != nil {
					if n, err := owner.Write(context.Background(), make([]byte, 64)); err != nil || n != 64 {
						t.Fatal("could not fill the original send ring", n, err)
					}
					beforeAccepted = 64
				}
				diagnostics.sink.mu.Lock()
				beforeEvents := diagnostics.sink.queued
				diagnostics.sink.mu.Unlock()
				timeout := uint64(3000)
				if tc.name == "deadline" {
					timeout = 100
				}
				input := []byte("original")
				op, err := owner.PrepareWrite(input, WriteOptions{TimeoutMS: timeout, HardDeadline: streamTestDeadline(t, f.local.engine)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(op.Cancel)
				op.mu.Lock()
				diagnostic := op.diagnosticOperation
				op.mu.Unlock()
				if diagnostic == nil {
					t.Fatal("completed writes exhausted the bounded diagnostic slots")
				}
				if err := op.Start(); err != nil {
					t.Fatal(err)
				}
				if tc.cause != nil {
					waitCtx, cancel := context.WithCancel(context.Background())
					cancel()
					progress, err := op.Wait(waitCtx)
					if !errors.Is(err, context.Canceled) || progress.Phase != protocolv4.V4WritePhaseRunning || progress.AcceptedBytes != 0 {
						t.Fatal("observer cancellation changed the original write", progress, err)
					}
					diagnostic.applicationMu.Lock()
					references := diagnostic.applicationReferences
					diagnostic.applicationMu.Unlock()
					if references != 1 || diagnostic.sink.Load() != diagnostics.sink {
						t.Fatal("observer cancellation retired the original diagnostic", references)
					}
				}
				switch tc.name {
				case "cancel":
					op.Cancel()
				case "stream_close":
					if err := owner.Close(); err != nil {
						t.Fatal(err)
					}
				}
				awaitWriteTerminal(t, op)
				// The done signal precedes the final sink retirement within the
				// same queue turn. Join that turn before inspecting cleanup.
				q.mu.Lock()
				q.mu.Unlock()
				progress, err := op.Wait(context.Background())
				accepted := uint64(0)
				if tc.cause == nil {
					accepted = uint64(len(input))
				}
				if !errors.Is(err, tc.cause) || progress.RequestedBytes != uint64(len(input)) || progress.AcceptedBytes != accepted || progress.TerminalReason != tc.reason || progress.CleanupStatus.Status != protocolv4.V4CleanupStateComplete || progress.CleanupStatus.CoreCleanup != protocolv4.V4CoreCleanupComplete || progress.CleanupStatus.PendingCallbacks != 0 {
					t.Fatal("write lost its exact terminal or cleanup outcome", progress, err)
				}
				if op.queue.Load() != nil || op.diagnosticOperation != nil || owner.AcceptedBytes() != beforeAccepted+accepted {
					t.Fatal("terminal write retained ownership or changed acceptance")
				}
				diagnostic.applicationMu.Lock()
				references := diagnostic.applicationReferences
				diagnostic.applicationMu.Unlock()
				if references != 0 || diagnostic.sink.Load() != nil {
					t.Fatal("terminal write retained its diagnostic slot", references)
				}
				wantEvents := uint32(2)
				if tc.cause != nil {
					wantEvents++
				}
				diagnostics.sink.mu.Lock()
				var events [3]diagnosticv4.Event
				added := diagnostics.sink.queued - beforeEvents
				for i := uint32(0); i < min(added, 3); i++ {
					events[i] = diagnostics.sink.queue[(diagnostics.sink.first+beforeEvents+i)%diagnostics.sink.policy.queue].event
				}
				live := 0
				for _, slot := range diagnostics.sink.operations {
					if slot.handle != nil {
						live++
					}
				}
				diagnostics.sink.mu.Unlock()
				if live != 0 || added != wantEvents {
					t.Fatal("write leaked a slot or emitted duplicate lifecycle events", live, added, wantEvents)
				}
				id := events[0].CorrelationID()
				if id == ([16]byte{}) || seen[id] {
					t.Fatal("new write reused a completed diagnostic identity")
				}
				seen[id] = true
				for i := uint32(0); i < wantEvents; i++ {
					wantState, wantCode := diagnosticv4.StateStarting, diagnosticv4.CodeOK
					if i == wantEvents-1 {
						wantState, wantCode = diagnosticv4.StateClosed, tc.code
					} else if i != 0 {
						wantState, wantCode = diagnosticv4.StateFailed, tc.code
					}
					fields := events[i].Fields()
					if events[i].CorrelationID() != id || fields.Phase != diagnosticv4.PhaseApplication || fields.State != wantState || fields.Code != wantCode {
						t.Fatal("write lifecycle diagnostic lost original outcome", fields, wantState, wantCode)
					}
				}
				op.Cancel()
				if err := op.Start(); !errors.Is(err, tc.cause) || op.Progress() != progress {
					t.Fatal("terminal observation changed original write", op.Progress(), err)
				}
				diagnostics.sink.mu.Lock()
				repeatedEvents := diagnostics.sink.queued - beforeEvents
				diagnostics.sink.mu.Unlock()
				if repeatedEvents != wantEvents {
					t.Fatal("repeated terminal observation emitted another diagnostic", repeatedEvents, wantEvents)
				}
			})
		}
	}
}
