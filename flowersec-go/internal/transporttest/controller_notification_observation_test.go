package transporttest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
)

func TestControllerNotificationPublicSubscriptionFollowsReplacement(t *testing.T) {
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
	if _, err = controller.WaitForSession(ctx); err != nil {
		t.Fatal(err)
	}
	firstServer, err := source.WaitServer(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	definition := fixture.definitions[source.ClientRuntime(0)]
	fixture.mu.Unlock()
	if definition == nil {
		t.Fatal("original admitted Controller definition is missing")
	}
	bound, err := controller.BindMethods(ctx, definition.Definition, fs.ServiceBindOptions{ContractSource: fs.ServiceContractsStatic})
	if err != nil {
		t.Fatal(err)
	}
	fixture.retainCleanup(func(ctx context.Context) error { bound.Close(); return bound.WaitCleanup(ctx) })
	events := make(chan fs.ControllerNotificationEvent, 16)
	subscription, err := controller.SubscribeNotification(bound, fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerNotification}, fs.ControllerNotificationObserver{
		Decode: func(_ context.Context, payload []byte) (any, error) {
			var value string
			err := json.Unmarshal(payload, &value)
			return value, err
		},
		Handle: func(ctx context.Context, event fs.ControllerNotificationEvent) error {
			select {
			case events <- event:
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		},
	}, fs.ControllerNotificationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.retainCleanup(func(ctx context.Context) error {
		subscription.Close()
		if err := subscription.WaitClosed(ctx); err != nil {
			return err
		}
		return subscription.Release()
	})
	waitAttached := func() {
		t.Helper()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for !subscription.ObservationStatus().AttachedCurrent {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatal("Controller observer never attached its actual current", context.Cause(ctx))
			}
		}
	}
	waitAttached()
	firstGeneration := subscription.ObservationStatus().CurrentGeneration
	notify := func(server *fs.ServiceClient, value string) fs.ControllerNotificationEvent {
		t.Helper()
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := server.NotifyMethod(ctx, fs.MethodSelector{Namespace: currentControllerHandlerNamespace, Type: currentControllerNotification}, payload, fs.OperationOptions{DefaultLifetimeMS: 15000}); err != nil || !result.NotificationSubmission.MessageAccepted {
			t.Fatal(result, err)
		}
		for {
			select {
			case event := <-events:
				if event.Kind == "notification" {
					if event.Value != value || event.SourcePhase != "current" {
						t.Fatal("incorrect Controller event", event)
					}
					return event
				}
			case <-ctx.Done():
				t.Fatal("Controller subscription missed its source", context.Cause(ctx))
				return fs.ControllerNotificationEvent{}
			}
		}
	}
	firstBound := fixture.bind(t, ctx, source.ServerRuntime(0), firstServer)
	if event := notify(firstBound, "first"); event.SourceGeneration != firstGeneration {
		t.Fatal("first source generation changed", event)
	}
	replaced, err := controller.ReplaceSession(ctx, fs.ControllerReplaceOptions{})
	if err != nil || !replaced.CurrentSwitched {
		t.Fatal("explicit replacement failed", replaced, err)
	}
	secondServer, err := source.WaitServer(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	waitAttached()
	secondBound := fixture.bind(t, ctx, source.ServerRuntime(1), secondServer)
	if event := notify(secondBound, "second"); event.SourceGeneration == firstGeneration {
		t.Fatal("new event reused the old source generation", event)
	}
	status := subscription.ObservationStatus()
	if status.Gap.Reasons&fs.NotificationGapHandoff == 0 || !status.Gap.PossibleGap {
		t.Fatal("replacement hid its observation boundary", status)
	}
	if err := subscription.ReplaceDependencies(ctx, nil); err != nil {
		t.Fatal("public observer declaration replacement", err)
	}
	subscription.Close()
	if err := subscription.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if status := subscription.ObservationStatus(); !status.Closed || !status.CleanupComplete {
		t.Fatal("public closed observation state", status)
	}
	if source.AcquisitionCount() != 2 || source.SpendCount(0) != 1 || source.SpendCount(1) != 1 {
		t.Fatal("subscription created extra acquisition or replay")
	}
}
