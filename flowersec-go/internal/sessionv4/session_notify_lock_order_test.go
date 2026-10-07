package sessionv4

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestPreparedNotifyPublicationPreservesInboundAuthorityLockOrder(t *testing.T) {
	f, services, _, _ := notifyWorkloadFixture(t, false)
	charge, err := rpcv4.ContractRouteCharge(services.runtimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	route, err := f.routes.Capture(f.policy.Digest, f.f.reserve(t, 1, charge), services.runtimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(route.Release)
	operation, err := services.PrepareNotifyOperation(context.Background(), route, []byte("original notification"), rpcv4.NotifyPreparation{
		UnaryPreparation: rpcv4.UnaryPreparation{DeadlineAtMS: 1500},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(operation.Close)
	attachNotifyWorkloadPublisher(t, f, services, 0)
	if started := operation.Start(context.Background()); started.Error != nil || started.NotAdmitted {
		t.Fatal("original notification was not admitted", started)
	}
	state := operation.owner.notify
	header := state.request.Header()
	_, authority, err := f.plan.queryAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	authorityDone := make(chan error, 1)
	go func() {
		authorityDone <- authority.WithCurrentAuthorizationSample(func(timev4.Sample) error {
			close(entered)
			<-release
			return nil
		})
	}()
	awaitApplicationTask(t, entered)
	published := make(chan error, 1)
	go func() {
		published <- state.WithNotifyPublicationProgress(header, false, func(reference resourcev4.Reference) error {
			return reference.Check()
		})
	}()

	// Observe the actual blocked publisher, rather than relying on scheduler
	// timing or adding a test hook to the authorization critical section.
	stack := make([]byte, 1<<20)
	end := time.Now().Add(3 * time.Second)
	for {
		blocked := false
		for _, goroutine := range strings.Split(string(stack[:runtime.Stack(stack, true)]), "\n\n") {
			if strings.Contains(goroutine, "(*notifyOperationState).WithNotifyPublicationProgress") &&
				strings.Contains(goroutine, "(*EndpointAuthorization).WithCurrentAuthorizationSample") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		if time.Now().After(end) {
			t.Fatal("publisher did not reach the held original authority")
		}
		runtime.Gosched()
	}
	registered := make(chan error, 1)
	go func() { registered <- route.WithRegistered(func() error { return nil }) }()
	select {
	case err := <-registered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		// Release the authority before failing so the negative control can
		// join both original operations and return all fixture resources.
		unblock()
		<-authorityDone
		<-published
		<-registered
		t.Fatal("notification publication held the route while waiting for authority")
	}
	unblock()
	if err := <-authorityDone; err != nil {
		t.Fatal(err)
	}
	if err := <-published; err != nil {
		t.Fatal(err)
	}
}
