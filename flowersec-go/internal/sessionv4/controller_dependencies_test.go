package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func TestControllerDeclaredRequiredUnionUsesCandidateWithoutRevokingCurrent(t *testing.T) {
	f, services, controller, sessions, _ := controllerReselectionFixture(t)
	client, err := controller.BindMethods(context.Background(), controllerServiceDefinition(f), UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	selector := UnaryMethodSelector{Namespace: f.policy.Namespace, Type: f.policy.Type}
	optional := invocationDeclarations(t, f.f, []ServiceDependency{{Alias: "optional", Client: client, Methods: []ServiceDependencyMethod{{Method: selector, DispatchRequirement: OnUse}}}})
	services[1].mu.Lock()
	channel := services[1].channel
	services[1].channel = nil
	services[1].mu.Unlock()
	finish, err := controller.qualifyDeclaredDependencies(context.Background(), sessions[1])
	if err != nil {
		t.Fatal("optional path blocked candidate", err)
	}
	finish()
	declaration := []ServiceDependency{{Alias: "required", Client: client, Methods: []ServiceDependencyMethod{{Method: selector}}}}
	first := invocationDeclarations(t, f.f, declaration)
	second := invocationDeclarations(t, f.f, declaration)
	if finish, err = controller.qualifyDeclaredDependencies(context.Background(), sessions[1]); !errors.Is(err, cryptov4.ErrNotReady) || finish != nil {
		t.Fatal("candidate lacked required real channel", err)
	}
	if current, err := controller.CaptureSession(); err != nil || current != sessions[0] {
		t.Fatal("new missing dependency revoked healthy current", err)
	}
	first.close()
	if finish, err = controller.qualifyDeclaredDependencies(context.Background(), sessions[1]); !errors.Is(err, cryptov4.ErrNotReady) || finish != nil {
		t.Fatal("closing one declaration canceled another's demand", err)
	}
	services[1].mu.Lock()
	services[1].channel = channel
	services[1].mu.Unlock()
	finish, err = controller.qualifyDeclaredDependencies(context.Background(), sessions[1])
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot changes and new declarations cannot race through publication.
	client.mu.Lock()
	_, gateErr := client.dependencyInstallGateLocked(&client.methods[0])
	client.mu.Unlock()
	if !errors.Is(gateErr, cryptov4.ErrNotReady) {
		finish()
		t.Fatal(gateErr)
	}
	finish()
	second.close()
	optional.close()
	client.mu.Lock()
	count := client.methods[0].requiredDeclarations.Load()
	client.mu.Unlock()
	if count != 0 {
		t.Fatal("closed declarations retained future demand", count)
	}
}

func TestControllerRejectedCandidateCannotSealHealthyBorrowedClient(t *testing.T) {
	f, services, controller, sessions, _ := controllerReselectionFixture(t)
	client, err := controller.BindMethods(context.Background(), controllerServiceDefinition(f), UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeControllerService(t, client) })
	invocationDeclarations(t, f.f, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: f.policy.Namespace, Type: f.policy.Type}}}}})
	services[1].mu.Lock()
	original := services[1].clock
	services[1].clock = nil
	services[1].mu.Unlock()
	finish, err := controller.qualifyDeclaredDependencies(context.Background(), sessions[1])
	services[1].mu.Lock()
	services[1].clock = original
	services[1].mu.Unlock()
	if finish != nil {
		finish()
	}
	if !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal(err)
	}
	if err := client.dependencyReady(context.Background(), f.policy.Type); err != nil {
		t.Fatal("rejected candidate sealed healthy original binding", err)
	}
}
