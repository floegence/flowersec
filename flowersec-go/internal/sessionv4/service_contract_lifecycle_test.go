package sessionv4

import (
	"context"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestContractAbnormalSampleReturnsOriginalVisit(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{{"panic", func() { panic("clock") }}, {"goexit", runtime.Goexit}} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, _, definition := serviceShapesFixture(t)
			client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			clock, err := timev4.NewClock(client.clock.Profile(), func() (timev4.Tick, error) {
				tc.exit()
				return timev4.Tick{}, timev4.ErrUnavailable
			})
			if err != nil {
				t.Fatal(err)
			}
			client.mu.Lock()
			client.clock = clock
			client.mu.Unlock()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				client.Contract(1)
			}()
			awaitApplicationTask(t, done)
			client.mu.Lock()
			visits := client.visits
			client.mu.Unlock()
			if visits != 0 {
				t.Fatal("abnormal sample retained its visit", visits)
			}
			client.Close()
			if !client.advance() {
				t.Fatal("returned sample prevented binding cleanup")
			}
		})
	}
}

func TestContractAbnormalContextSetupSettlesUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{{"panic", func() { panic("context") }}, {"goexit", runtime.Goexit}} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, e, definition, variants := serviceMethodsFixture(t, 1)
			client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			ctx := &serviceClientSetupContext{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{}), exit: tc.exit}
			close(ctx.resume)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_, _ = client.UpdateContract(ctx, 1, variants[0])
			}()
			awaitApplicationTask(t, done)
			client.mu.Lock()
			leaked := client.visits != 0 || client.methods[0].update.done != nil
			client.mu.Unlock()
			e.mu.Lock()
			work := e.staticContractWork
			e.mu.Unlock()
			if leaked || work != 0 {
				t.Fatal("abnormal setup retained the original update or Environment work")
			}
			if _, err := client.UpdateContract(context.Background(), 1, variants[0]); err != nil {
				t.Fatal("abnormal prior caller prevented a new explicit update", err)
			}
		})
	}
}

func TestContractAbnormalJoinKeepsOriginalInitiator(t *testing.T) {
	_, r, _, definition, variants := serviceMethodsFixture(t, 1)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	block := &serviceCallReadBlock{entered: make(chan struct{}), resume: make(chan struct{})}
	defer block.release()
	initiator := &serviceClientSetupContext{Context: context.Background(), entered: block.entered, resume: block.resume}
	finished := make(chan struct{})
	var updateErr error
	go func() { defer close(finished); _, updateErr = client.UpdateContract(initiator, 1, variants[0]) }()
	awaitApplicationTask(t, block.entered)
	observer := &serviceClientSetupContext{Context: context.Background(), entered: make(chan struct{}), resume: make(chan struct{}), exit: runtime.Goexit}
	close(observer.resume)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = client.UpdateContract(observer, 1, variants[0]) }()
	awaitApplicationTask(t, done)
	client.mu.Lock()
	u := client.methods[0].update
	visits := client.visits
	client.mu.Unlock()
	if !u.active || u.waiters != 0 || visits != 1 {
		t.Fatal("abnormal observer canceled the initiator or retained a waiter", u.active, u.waiters, visits)
	}
	block.release()
	awaitApplicationTask(t, finished)
	if updateErr != nil {
		t.Fatal("original initiator could not complete", updateErr)
	}
}

func TestContractVisitRetainsBlockedObserverCapacity(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var owners [4]*serviceCallCancellation
	var blocks [4]*serviceCallReadBlock
	for j := range owners {
		input := newServiceCallOpaqueContext(context.Canceled)
		t.Cleanup(func() { input.cancel(context.Canceled) })
		client.mu.Lock()
		visit, err := client.reserveContractVisitLocked(input)
		client.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := visit.start(nil); err != nil {
			t.Fatal(err)
		}
		owners[j] = visit.cancellation
		b := &serviceCallReadBlock{entered: make(chan struct{}), resume: make(chan struct{})}
		blocks[j] = b
		t.Cleanup(b.release)
		input.block.Store(b)
		input.cancel(context.Canceled)
		awaitApplicationTask(t, b.entered)
		client.leaveContractVisit(visit)
	}
	client.mu.Lock()
	_, err = client.reserveContractVisitLocked(context.Background())
	client.mu.Unlock()
	if err != cryptov4.ErrCapacity {
		t.Fatal("caller return recycled a blocked cancellation observer", err)
	}
	client.Close()
	if client.advance() {
		t.Fatal("Close refunded actual cancellation reads")
	}
	for j, b := range blocks {
		b.release()
		awaitApplicationTask(t, owners[j].done)
	}
	if !client.advance() {
		t.Fatal("actual observer exits did not return the binding")
	}
}

func TestRemoteBatchAbnormalExitDoesNotSealLaterUpdate(t *testing.T) {
	_, r, _, definition, _ := serviceMethodsFixture(t, 2)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	batch := []*boundUnaryMethod{&client.methods[0], &client.methods[1]}
	client.mu.Lock()
	for _, m := range batch {
		m.update = serviceContractUpdate{active: true, done: make(chan struct{})}
	}
	client.mu.Unlock()
	owners := client.captureRemoteBatchOwners(batch)
	client.mu.Lock()
	completeContractUpdateLocked(&batch[0].update, UnaryContractSnapshot{Type: 1}, nil)
	later := make(chan struct{})
	batch[0].update = serviceContractUpdate{active: true, done: later}
	client.mu.Unlock()
	client.abortRemoteBatch(batch, owners)
	client.mu.Lock()
	preserved := batch[0].update.active && batch[0].update.done == later
	settled := !batch[1].update.active && batch[1].update.done == nil
	completeContractUpdateLocked(&batch[0].update, UnaryContractSnapshot{Type: 1}, nil)
	client.mu.Unlock()
	if !preserved || !settled {
		t.Fatal("abandoned batch changed a different update or retained its own")
	}
}
