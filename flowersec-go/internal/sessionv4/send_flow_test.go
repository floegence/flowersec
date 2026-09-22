package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestSendFlowCreditAndTerminalFacts(t *testing.T) {
	wire := newFlowTransport(t)
	send, err := testSendFlow(t, wire.writer, protocolv4.ClientToServer, 3, TerminalTuple{}, 64, 128)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := send.Write(context.Background(), []byte("four"), false); !errors.Is(err, ErrCredit) || result.Submitted {
		t.Fatal("over-credit ticket", result, err)
	}
	if result, err := send.Write(context.Background(), []byte("abc"), false); err != nil || !result.Complete || result.Header.Sequence != 0 {
		t.Fatal(result, err)
	}
	if err = send.ApplyCredit(4, 8); !errors.Is(err, ErrCredit) {
		t.Fatal("over ACK", err)
	}
	if err = send.ApplyCredit(3, 8); err != nil {
		t.Fatal(err)
	}
	if err = send.ApplyCredit(2, 8); !errors.Is(err, ErrCredit) {
		t.Fatal("rollback", err)
	}
	if result, err := send.Write(context.Background(), []byte("def"), true); err != nil || !result.Complete || result.Header.Sequence != 1 {
		t.Fatal(result, err)
	}
	terminal, ok := send.Terminal()
	if !ok || terminal != (TerminalTuple{NextSequence: 2, Offset: 6}) {
		t.Fatal(terminal, ok)
	}
	if _, err = send.Write(context.Background(), nil, false); !errors.Is(err, ErrFlowClosed) {
		t.Fatal("FIN reopened", err)
	}
	if err = send.ApplyCredit(6, 16); err != nil {
		t.Fatal(err)
	}
	if err = send.ApplyCredit(6, 12); !errors.Is(err, ErrCredit) {
		t.Fatal("late limit rollback", err)
	}
	if err = send.AdvanceEpoch(1); err != nil {
		t.Fatal(err)
	}
	retained, _ := send.Terminal()
	if retained != terminal {
		t.Fatal("terminal epoch overwritten")
	}
	proof := DrainProof{Terminal: terminal, Observed: terminal}
	if err = send.ApplyDrained(proof); err != nil {
		t.Fatal(err)
	}
	if err = send.ApplyDrained(proof); err != nil {
		t.Fatal("duplicate proof", err)
	}
	_, ack, _, drained, cleanup := send.Snapshot()
	if ack != 6 || !drained || !cleanup {
		t.Fatal(ack, drained, cleanup)
	}
	if err = send.ApplyDrained(DrainProof{Terminal: terminal, Observed: TerminalTuple{NextSequence: 1, Offset: 3}, Aborted: true}); !errors.Is(err, ErrTerminal) {
		t.Fatal("changed final proof", err)
	}
}

func TestSendFlowStopWaitRetainsProviderTail(t *testing.T) {
	engine := ioEngine(t, protocolv4.ClientToServer)
	provider := &blockedWriter{make(chan struct{}), make(chan struct{})}
	writer, _ := NewRecordWriter(engine, 1, provider)
	flow, err := testSendFlow(t, writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result RecordWriteResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, e := flow.Write(context.Background(), []byte("owned until actual provider exit"), false)
		done <- outcome{r, e}
	}()
	<-provider.entered
	flow.Stop()
	if _, ok := flow.Terminal(); ok {
		t.Fatal("terminal published while original provider still owned the operation")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = flow.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("wait canceled lost actual responsibility", err)
	}
	if _, err = flow.Write(context.Background(), nil, false); !errors.Is(err, ErrFlowClosed) {
		t.Fatal(err)
	}
	close(provider.finish)
	result := <-done
	if result.err == nil || !result.result.Submitted || result.result.EnvelopeBytes != 2 || result.result.Complete {
		t.Fatal(result)
	}
	terminal, ok := flow.Terminal()
	if !ok || terminal.NextSequence != 1 || terminal.Offset == 0 {
		t.Fatal("lost submitted frontier", terminal, ok)
	}
	if err = flow.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = flow.ApplyDrained(DrainProof{Terminal: terminal, Observed: TerminalTuple{}, Aborted: true}); err != nil {
		t.Fatal(err)
	}
	_, ack, _, drained, cleanup := flow.Snapshot()
	if ack != 0 || drained || !cleanup {
		t.Fatal("aborted proof invented receipt", ack, drained, cleanup)
	}
}

func TestSendFlowFailedEncodingSpendsOnlyOriginalTicket(t *testing.T) {
	wire := newFlowTransport(t)
	flow, err := testSendFlow(t, wire.writer, protocolv4.ClientToServer, 1, TerminalTuple{}, 1, 128)
	if err != nil {
		t.Fatal(err)
	}
	// Fault injection after admission: the constructor now rejects this bound.
	// A broken internal builder must still preserve its irreversibly spent ticket.
	flow.maxPlaintext = 1
	result, err := flow.Write(context.Background(), []byte("x"), false)
	if err == nil || !result.Submitted || result.Complete || wire.wire.Len() != 0 {
		t.Fatal(result, err)
	}
	terminal, ok := flow.Terminal()
	if !ok || terminal.NextSequence != 1 || terminal.Offset != 0 {
		t.Fatal(terminal, ok)
	}
	if _, err = flow.Write(context.Background(), nil, false); !errors.Is(err, ErrFlowClosed) {
		t.Fatal(err)
	}
	if err = flow.AdvanceEpoch(1); errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("failed ticket retained a phantom job", err)
	}
}
