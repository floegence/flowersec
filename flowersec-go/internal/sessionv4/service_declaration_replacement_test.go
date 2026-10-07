package sessionv4

import (
	"context"
	"errors"
	"testing"
)

func TestServiceDeclarationReplacementRetainsEnteredContextAndSelectedView(t *testing.T) {
	f, rpc, _, definition := serviceShapesFixture(t)
	client, err := rpc.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	registered := f.dispatch.methods[0].registration
	selector := UnaryMethodSelector{Namespace: registered.Namespace, Type: registered.Type}
	method := UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}
	declarations := []ServiceDependency{{Alias: "original", Client: client, Methods: []ServiceDependencyMethod{{Method: method, DispatchRequirement: OnUse}}}}
	if err := f.dispatch.ReplaceDependencies(context.Background(), selector, declarations); err != nil {
		t.Fatal(err)
	}
	f.dispatch.mu.Lock()
	previous := f.dispatch.methods[0].registration.services
	f.dispatch.mu.Unlock()
	primary := previous.primary
	runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
		if err := attachInvocationServices(ctx, previous); err != nil {
			t.Fatal(err)
		}
		view, err := InvocationServiceFromContext(ctx, "original")
		if err != nil {
			t.Fatal(err)
		}
		_, selected, err := view.selectMethod(ctx, method)
		if err != nil {
			t.Fatal(err)
		}
		defer selected.Release()
		if err := f.dispatch.ReplaceDependencies(ctx, selector, nil); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal("invocation acquired a registration control", err)
		}
		next := []ServiceDependency{{Alias: "replacement", Client: client, Methods: []ServiceDependencyMethod{{Method: method, DispatchRequirement: OnUse}}}}
		if err := f.dispatch.ReplaceDependencies(context.Background(), selector, next); err != nil {
			t.Fatal(err)
		}
		if !previous.closed || previous.bindings == nil || primary.Check() != nil || selected.registration.Check() != nil {
			t.Fatal("replacement refunded an actual old invocation/view")
		}
		if _, err := InvocationServiceFromContext(ctx, "replacement"); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal("live context silently changed declaration generation", err)
		}
		if _, _, err := view.selectMethod(ctx, method); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal("closed declaration allowed a new child selection", err)
		}
		selected.Release()
		if previous.bindings == nil || primary.Check() != nil {
			t.Fatal("view exit refunded its still-entered application context")
		}
	})
	if previous.bindings != nil || primary.Check() == nil {
		t.Fatal("actual context exit did not release replaced declaration")
	}
	f.dispatch.mu.Lock()
	current := f.dispatch.methods[0].registration.services
	f.dispatch.mu.Unlock()
	if current == previous || current.closed || current.bindings[0].alias != "replacement" {
		t.Fatal("replacement did not publish its own immutable declaration")
	}
	if len(f.sink.wire) != 0 {
		t.Fatal("declaration replacement created hidden network preparation")
	}
}

func TestControllerObserverDeclarationReplacementKeepsOldCallbackOwner(t *testing.T) {
	f := newControllerNotificationFixture(t, NotificationCurrentOnly, NotificationDropNewest, ControllerNotificationObserver{Decode: func(_ context.Context, p []byte) (any, error) { return string(p), nil }, Handle: func(context.Context, ControllerNotificationEvent) error { return nil }})
	declarations := []ServiceDependency{{Alias: "observe", Client: f.root.client, Methods: []ServiceDependencyMethod{{Method: f.root.selector, DispatchRequirement: OnUse}}}}
	if err := f.root.subscription.ReplaceDependencies(context.Background(), declarations); err != nil {
		t.Fatal(err)
	}
	f.root.mu.Lock()
	previous := f.root.services
	f.root.mu.Unlock()
	if err := previous.retainRegistration(); err != nil {
		t.Fatal(err)
	}
	primary := previous.primary
	if err := f.root.subscription.ReplaceDependencies(context.Background(), nil); err != nil {
		previous.releaseInvocation()
		t.Fatal(err)
	}
	if !previous.closed || primary.Check() != nil || previous.bindings == nil {
		previous.releaseInvocation()
		t.Fatal("observer replacement dropped the running declaration owner")
	}
	previous.releaseInvocation()
	if primary.Check() == nil || previous.bindings != nil {
		t.Fatal("observer declaration outlived its final actual callback visit")
	}
	f.root.Close()
	if err := f.root.subscription.ReplaceDependencies(context.Background(), declarations); err == nil {
		t.Fatal("closed observer accepted a new declaration")
	}
}
