package rpcv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type renewalQueryGuard struct{}

func (renewalQueryGuard) WithRequestPublication(_ protocolv4.ApplicationHeader, action func() error) error {
	return action()
}

func TestContractQueryRenewalProtectsOriginalQ2AndConsumerTail(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	a, b := newRPCFixture(t, contract, 1), newRPCFixture(t, contract, 1)
	client := installQueryClient(t, a)
	service := installQueryService(t, b)
	initiator, err := client.ClaimInitiator(make(chan struct{}, 1), client.reservation)
	if err != nil {
		t.Fatal(err)
	}
	protection, err := initiator.ProtectRenewal(a.reserve(ContractQueryRenewalCharge()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(protection.Close)
	secondProtection, err := initiator.ProtectRenewal(a.reserve(ContractQueryRenewalCharge()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondProtection.Close)
	policy, _ := contract.Policy()
	targets := []protocolv4.ContractQueryTarget{{Namespace: policy.Namespace, Type: policy.Type}}
	known := []protocolv4.ContractQueryKnown{nil}
	ordinary, err := initiator.Begin(a.p, targets, known, 50000)
	if err != nil || ordinary.index != 0 {
		t.Fatal(ordinary, err)
	}
	ordinary.Close()
	finishPublisher(t, a)
	ordinary, err = initiator.Begin(a.p, targets, known, 50000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = initiator.Begin(a.p, targets, known, 50000); err != ErrCapacity {
		t.Fatal("ordinary query consumed renewal Q", err)
	}
	if _, err = protection.Begin(a.p, targets, known, 50000, renewalQueryGuard{}); err != ErrConfiguration {
		t.Fatal("advertisement used renewal Q", err)
	}
	ordinary.Close()
	finishPublisher(t, a)
	targets[0].HasWanted, targets[0].Wanted = true, policy.Digest
	renewal, err := protection.Begin(a.p, targets, known, 50000, renewalQueryGuard{})
	if err != nil || renewal.index != 1 {
		t.Fatal(renewal, err)
	}
	if err = renewal.RetainConsumer(); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, a, b)
	pumpRPC(t, a, b)
	job := resolveQuery(t, service, QueryTargetAllowed)
	if err = publishQuery(job); err != nil {
		t.Fatal(err)
	}
	pumpRPC(t, b, a)
	pumpRPC(t, b, a)
	renewal.Close()
	finishPublisher(t, a)
	finishPublisher(t, b)
	if renewal.CleanupComplete() {
		t.Fatal("consumer output no longer owned Q2")
	}
	if _, err = secondProtection.Begin(a.p, targets, known, 50000, renewalQueryGuard{}); err != ErrCapacity {
		t.Fatal(err)
	}
	protection.Close()
	if _, err = initiator.Begin(a.p, targets, known, 50000); err != nil {
		t.Fatal("ordinary position unavailable", err)
	}
	if _, err = initiator.Begin(a.p, targets, known, 50000); err != ErrCapacity {
		t.Fatal("second binding lost protection", err)
	}
	client.Close()
	if client.CleanupComplete() {
		t.Fatal("client discarded retained renewal owner")
	}
	renewal.ReleaseConsumer()
	secondProtection.Close()
	a.sink.published = true
	for range 8 {
		_, _ = a.p.Step(context.Background())
	}
	if !client.CleanupComplete() {
		t.Fatal("client retained completed renewal")
	}
}

func TestContractQueryRenewalCannotDisplaceExistingSecondVector(t *testing.T) {
	_, contract, _ := inputFixture(t, false, nil)
	defer contract.Release()
	f := newRPCFixture(t, contract, 1)
	client := installQueryClient(t, f)
	x, err := client.ClaimInitiator(make(chan struct{}, 1), client.reservation)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := contract.Policy()
	targets := []protocolv4.ContractQueryTarget{{Namespace: policy.Namespace, Type: policy.Type}}
	for range 2 {
		if _, err = x.Begin(f.p, targets, []protocolv4.ContractQueryKnown{nil}, 50000); err != nil {
			t.Fatal(err)
		}
	}
	ref := f.reserve(ContractQueryRenewalCharge())
	defer ref.Release()
	if _, err = x.ProtectRenewal(ref); !errors.Is(err, ErrCapacity) || ref.Check() != nil {
		t.Fatal("protection displaced original query", err)
	}
}
