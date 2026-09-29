package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func TestRequiredDeclarationSharesExplicitPoolAndCountsClosingEntries(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	core, err := r.bindingCore()
	if err != nil {
		t.Fatal(err)
	}
	p := core.plan
	stream := definition.Methods[1]
	binding := preacceptedBinding(stream.StreamKind, stream.StreamMetadata, stream.Method.Contract)
	for i := 0; i < 2; i++ {
		entry := &preacceptedStream{allocation: &sessionStreamAllocation{}, binding: [32]byte{byte(i + 1)}}
		entry.namespaceBytes = copy(entry.namespace[:], definition.Namespace)
		p.preaccepted[i] = entry
	}
	t.Cleanup(func() { p.mu.Lock(); clear(p.preaccepted[:]); p.mu.Unlock() })
	declarations := []ServiceDependency{{Alias: "events", Client: client, Methods: []ServiceDependencyMethod{{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: stream.Type}}}}}
	charge, _ := serviceDependenciesCharge(declarations)
	backing := f.f.reserve(t, 1, charge)
	if s, err := newInvocationServices(declarations, backing); s != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("declaration borrowed positions already occupied by explicit entries", err)
	}
	p.mu.Lock()
	p.preaccepted[0].binding = binding
	p.mu.Unlock()
	s, err := newInvocationServices(declarations, backing)
	if err != nil {
		t.Fatal("exact existing entry did not cover the required target", err)
	}
	t.Cleanup(s.close)
	p.mu.Lock()
	p.preaccepted[1] = nil
	p.mu.Unlock()
	finish, err := p.preacceptedCapacityGate([32]byte{31}, stream.Method.Contract, false)
	if err != nil {
		t.Fatal("one explicit entry and one shared required target did not fit", err)
	}
	finish()
	p.mu.Lock()
	p.preaccepted[0].mu.Lock()
	p.preaccepted[0].closed = true
	p.preaccepted[0].mu.Unlock()
	p.mu.Unlock()
	if finish, err := p.preacceptedCapacityGate([32]byte{31}, stream.Method.Contract, false); finish != nil || !errors.Is(err, cryptov4.ErrCapacity) {
		if finish != nil {
			finish()
		}
		t.Fatal("closing entry either refunded capacity or promised availability", err)
	}
	// Replenishing that exact required target needs only the closing physical
	// entry plus its replacement, rather than a third independent promise.
	finish, err = p.preacceptedCapacityGate(binding, stream.Method.Contract, true)
	if err != nil {
		t.Fatal("required replacement counted itself twice", err)
	}
	finish()
}
