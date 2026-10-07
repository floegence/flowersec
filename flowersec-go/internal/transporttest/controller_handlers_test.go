package transporttest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const currentControllerHandlerNamespace = "flowersec.engineering.controller"
const (
	currentControllerClientRPC    uint32 = 901
	currentControllerNotification uint32 = 902
	currentControllerPendingRPC   uint32 = 903
	currentControllerServerRPC    uint32 = 904
)

type currentControllerHandlerFixture struct {
	mu                                            sync.Mutex
	definitions                                   map[*interopharness.Runtime]*interopharness.RPCDefinition
	cleanups                                      []func(context.Context) error
	clientCalls, serverCalls                      atomic.Int32
	pendingStarted, pendingExited, pendingRelease chan struct{}
	started, exited                               sync.Once
}

func newCurrentControllerHandlerFixture() *currentControllerHandlerFixture {
	return &currentControllerHandlerFixture{definitions: make(map[*interopharness.Runtime]*interopharness.RPCDefinition), pendingStarted: make(chan struct{}), pendingExited: make(chan struct{}), pendingRelease: make(chan struct{})}
}
func (f *currentControllerHandlerFixture) configure(r *interopharness.Runtime, role uint8) (fs.StreamHandlerPlanConfig, error) {
	unary := func(kind uint32) interopharness.RPCMethod {
		return interopharness.RPCMethod{Type: kind, MaxEncodedBytes: 4096, Handle: func(ctx context.Context, input []byte) ([]byte, error) {
			var request map[string]string
			if err := json.Unmarshal(input, &request); err != nil {
				return nil, err
			}
			switch kind {
			case currentControllerClientRPC:
				if role != 0 {
					return nil, errors.New("client handler was dispatched at the wrong authenticated endpoint")
				}
				return json.Marshal(map[string]any{"generation": f.clientCalls.Add(1), "request": request})
			case currentControllerServerRPC:
				if role != 1 {
					return nil, errors.New("server handler was dispatched at the wrong authenticated endpoint")
				}
				f.serverCalls.Add(1)
				return append([]byte(nil), input...), nil
			case currentControllerPendingRPC:
				if role != 1 {
					return nil, errors.New("pending handler was dispatched at the wrong endpoint")
				}
				if request["phase"] != "pending" {
					return append([]byte(nil), input...), nil
				}
				f.started.Do(func() { close(f.pendingStarted) })
				defer f.exited.Do(func() { close(f.pendingExited) })
				select {
				case <-f.pendingRelease:
					return []byte(`{"late":true}`), nil
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}
			return nil, errors.New("unknown original controller method")
		}}
	}
	definition := interopharness.ConfigureRPC(r, role, currentControllerHandlerNamespace, []interopharness.RPCMethod{unary(currentControllerClientRPC), {Type: currentControllerNotification, MaxEncodedBytes: 4096, Notify: true}, unary(currentControllerPendingRPC), unary(currentControllerServerRPC)})
	f.mu.Lock()
	f.definitions[r] = definition
	f.mu.Unlock()
	return fs.StreamHandlerPlanConfig{RuntimeBytes: 16384}, nil
}
func (f *currentControllerHandlerFixture) bind(t *testing.T, ctx context.Context, r *interopharness.Runtime, session *fs.Session) *fs.ServiceClient {
	t.Helper()
	f.mu.Lock()
	definition := f.definitions[r]
	f.mu.Unlock()
	if definition == nil {
		t.Fatal("original admitted runtime has no immutable method definition")
	}
	bound, err := definition.Bind(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	f.retainCleanup(func(ctx context.Context) error { bound.Close(); return bound.WaitCleanup(ctx) })
	return bound
}
func currentControllerCall(t *testing.T, ctx context.Context, bound *fs.ServiceClient, kind uint32, payload []byte) []byte {
	t.Helper()
	result, err := bound.CallMethod(ctx, fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: kind}, payload, fs.OperationOptions{DefaultLifetimeMS: 15000})
	if err = errors.Join(err, result.Err); err != nil {
		t.Fatalf("original controller RPC result: %+v %v", result, err)
	}
	// Result delivery may precede original call cleanup. fixture.close joins
	// the public binding's physical cleanup after all generation checks.
	return result.Payload
}
func (f *currentControllerHandlerFixture) subscribe(t *testing.T, session *fs.Session, events chan<- string) *fs.NotificationSubscription {
	t.Helper()
	subscription, err := session.SubscribeNotification(fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerNotification}, fs.NotificationDropNewest, fs.NotificationObserver{Decode: func(_ context.Context, payload []byte) (any, error) {
		var phase string
		err := json.Unmarshal(payload, &phase)
		return phase, err
	}, Handle: func(ctx context.Context, value any) error {
		phase, ok := value.(string)
		if !ok {
			return errors.New("notification codec did not produce its declared value")
		}
		select {
		case events <- phase:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.retainCleanup(func(ctx context.Context) error {
		subscription.Close()
		if err := subscription.WaitClosed(ctx); err != nil {
			return err
		}
		return subscription.Release()
	})
	return subscription
}
func currentControllerNotify(t *testing.T, ctx context.Context, bound *fs.ServiceClient, events <-chan string, phase string) {
	t.Helper()
	payload, err := json.Marshal(phase)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bound.NotifyMethod(ctx, fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerNotification}, payload, fs.OperationOptions{DefaultLifetimeMS: 15000})
	if err != nil || !result.NotificationSubmission.MessageAccepted {
		t.Fatalf("original notification submission: %+v %v", result, err)
	}
	// Submission is a snapshot. The original binding cleanup is joined by
	// fixture.close after peer delivery and generation isolation are checked.
	select {
	case actual := <-events:
		if actual != phase {
			t.Fatalf("notification crossed generations: %q", actual)
		}
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	}
}

func TestConnectionControllerWebSocketHandlersSurviveTwoGenerations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fixture := newCurrentControllerHandlerFixture()
	endpoint, err := OpenProductDirectEndpointWithHandlers(ctx, carrier.KindWebSocket, fixture.configure)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	}()
	source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin, ControllerPlanCurrentPin}, fixture.configure)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	controller, err := source.NewController(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeControllerTest(t, controller)
	defer fixture.close(t)
	if err = controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := controller.WaitForSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstServer, err := source.WaitServer(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstClientRPC := fixture.bind(t, ctx, source.ClientRuntime(0), first)
	firstServerRPC := fixture.bind(t, ctx, source.ServerRuntime(0), firstServer)
	firstClientEvents, firstServerEvents := make(chan string, 4), make(chan string, 4)
	firstObserver := fixture.subscribe(t, first, firstClientEvents)
	firstServerObserver := fixture.subscribe(t, firstServer, firstServerEvents)
	var response struct {
		Generation int32             `json:"generation"`
		Request    map[string]string `json:"request"`
	}
	if err = json.Unmarshal(currentControllerCall(t, ctx, firstServerRPC, currentControllerClientRPC, []byte(`{"phase":"first"}`)), &response); err != nil || response.Generation != 1 || response.Request["phase"] != "first" {
		t.Fatalf("first server-to-client handler: %+v %v", response, err)
	}
	if reply := currentControllerCall(t, ctx, firstClientRPC, currentControllerServerRPC, []byte(`{"phase":"first"}`)); !bytes.Equal(reply, []byte(`{"phase":"first"}`)) {
		t.Fatal("first client-to-server handler changed payload")
	}
	currentControllerNotify(t, ctx, firstServerRPC, firstClientEvents, "first-client")
	currentControllerNotify(t, ctx, firstClientRPC, firstServerEvents, "first-server")
	pending := make(chan error, 1)
	pendingJoined := make(chan struct{})
	go func() {
		defer close(pendingJoined)
		result, err := firstClientRPC.CallMethod(ctx, fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerPendingRPC}, []byte(`{"phase":"pending"}`), fs.OperationOptions{DefaultLifetimeMS: 15000})
		pending <- errors.Join(err, result.Err)
	}()
	t.Cleanup(func() {
		select {
		case <-pendingJoined:
		case <-time.After(5 * time.Second):
			t.Error("old pending RPC retained its original caller")
		}
	})
	select {
	case <-fixture.pendingStarted:
	case <-ctx.Done():
		t.Fatal("pending RPC did not reach the real server handler")
	}
	resume, err := source.PausePreparations()
	if err != nil {
		t.Fatal(err)
	}
	defer resume()
	restart, stop := context.WithTimeout(ctx, 5*time.Second)
	err = endpoint.RestartListener(restart)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	resume()
	select {
	case err := <-pending:
		if err == nil {
			t.Fatal("old pending RPC unexpectedly succeeded after native disconnect")
		}
	case <-ctx.Done():
		t.Fatal("old pending RPC did not terminate")
	}
	select {
	case <-fixture.pendingExited:
	case <-ctx.Done():
		t.Fatal("old server handler retained its actual callback")
	}
	second := waitCurrentControllerReplacement(t, ctx, controller, first)
	secondServer, err := source.WaitServer(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || firstServer == secondServer {
		t.Fatal("controller reused a previous Session handle")
	}
	secondClientRPC := fixture.bind(t, ctx, source.ClientRuntime(1), second)
	secondServerRPC := fixture.bind(t, ctx, source.ServerRuntime(1), secondServer)
	secondClientEvents, secondServerEvents := make(chan string, 4), make(chan string, 4)
	fixture.subscribe(t, second, secondClientEvents)
	fixture.subscribe(t, secondServer, secondServerEvents)
	if err = json.Unmarshal(currentControllerCall(t, ctx, secondServerRPC, currentControllerClientRPC, []byte(`{"phase":"second"}`)), &response); err != nil || response.Generation != 2 || response.Request["phase"] != "second" {
		t.Fatalf("second server-to-client handler: %+v %v", response, err)
	}
	if reply := currentControllerCall(t, ctx, secondClientRPC, currentControllerServerRPC, []byte(`{"phase":"second"}`)); !bytes.Equal(reply, []byte(`{"phase":"second"}`)) {
		t.Fatal("second client-to-server handler changed payload")
	}
	currentControllerNotify(t, ctx, secondServerRPC, secondClientEvents, "second-client")
	currentControllerNotify(t, ctx, secondClientRPC, secondServerEvents, "second-server")
	close(fixture.pendingRelease)
	if fixture.clientCalls.Load() != 2 || fixture.serverCalls.Load() != 2 || source.AcquisitionCount() != 2 || source.SpendCount(0) != 1 || source.SpendCount(1) != 1 {
		t.Fatal("generation change replayed a handler or reused its original source spend")
	}
	if result, err := firstClientRPC.CallMethod(ctx, fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerServerRPC}, []byte(`{"phase":"old"}`), fs.OperationOptions{DefaultLifetimeMS: 15000}); err == nil && result.Err == nil {
		t.Fatal("old bound service migrated into the replacement")
	}
	for _, observer := range []*fs.NotificationSubscription{firstObserver, firstServerObserver} {
		observer.Close()
		if err := observer.WaitClosed(ctx); err != nil {
			t.Fatal(err)
		}
		if !observer.Status().CleanupComplete {
			t.Fatal("old notification observer retained a callback")
		}
	}
	for _, events := range []<-chan string{firstClientEvents, firstServerEvents} {
		select {
		case <-events:
			t.Fatal("replacement notification entered an old observer")
		default:
		}
	}
}

func (f *currentControllerHandlerFixture) retainCleanup(cleanup func(context.Context) error) {
	f.mu.Lock()
	f.cleanups = append(f.cleanups, cleanup)
	f.mu.Unlock()
}
func (f *currentControllerHandlerFixture) close(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	cleanups := f.cleanups
	f.cleanups = nil
	f.mu.Unlock()
	for index := len(cleanups) - 1; index >= 0; index-- {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		err := cleanups[index](ctx)
		stop()
		if err != nil {
			t.Errorf("original controller application owner cleanup: %v", err)
		}
	}
}
