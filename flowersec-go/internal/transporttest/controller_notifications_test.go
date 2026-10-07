package transporttest

import (
	"context"
	"encoding/json"
	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"testing"
	"time"
)

func TestDynamicNotificationsShareInboundRouter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin}, fixture.configure)
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
	client, err := controller.WaitForSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server, err := source.WaitServer(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	bound := fixture.bind(t, ctx, source.ServerRuntime(0), server)
	registeredEvents, dynamicEvents := make(chan string, 4), make(chan string, 4)
	fixture.subscribe(t, client, registeredEvents)
	dynamic := fixture.subscribe(t, client, dynamicEvents)
	panicking, err := client.SubscribeNotification(fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerNotification}, fs.NotificationDropNewest, fs.NotificationObserver{Decode: func(_ context.Context, payload []byte) (any, error) {
		var value string
		err := json.Unmarshal(payload, &value)
		return value, err
	}, Handle: func(context.Context, any) error { panic("isolated application observer") }})
	if err != nil {
		t.Fatal(err)
	}
	fixture.retainCleanup(func(ctx context.Context) error {
		panicking.Close()
		if err := panicking.WaitClosed(ctx); err != nil {
			return err
		}
		return panicking.Release()
	})
	currentControllerNotify(t, ctx, bound, registeredEvents, "first")
	select {
	case value := <-dynamicEvents:
		if value != "first" {
			t.Fatalf("dynamic observer payload: %q", value)
		}
	case <-ctx.Done():
		t.Fatal("dynamic original subscription missed peer notification")
	}
	dynamic.Close()
	dynamic.Close()
	if err = dynamic.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	currentControllerNotify(t, ctx, bound, registeredEvents, "second")
	select {
	case <-dynamicEvents:
		t.Fatal("closed original notification observer ran again")
	default:
	}
	if source.AcquisitionCount() != 1 || source.SpendCount(0) != 1 {
		t.Fatal("notification observers displaced the admitted Session or its once-only spend")
	}
}
