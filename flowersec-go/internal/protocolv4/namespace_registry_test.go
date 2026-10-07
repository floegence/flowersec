package protocolv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func registryFixture(t *testing.T, profile VerificationContinuity, entries uint32, prepare ...func(*onlineBootstrapFixture)) (*onlineBootstrapFixture, *NamespaceRegistry) {
	t.Helper()
	var registry *NamespaceRegistry
	setup := func(f *onlineBootstrapFixture) {
		c := NamespaceRegistryConfig{Continuity: profile, Entries: entries, RuntimeBytes: 4096}
		cost, err := NamespaceRegistryCharge(c)
		if err != nil {
			t.Fatal(err)
		}
		registry, err = NewNamespaceRegistry(c, f.namespace.reserve(t, cost))
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.Register(f.owner); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			registry.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for _, entry := range registry.entries[:registry.used] {
				if n := entry.trust.namespace; n != nil {
					if err := n.WaitCleanup(ctx); err != nil {
						t.Error(err)
					}
				}
			}
			f.namespace.resources.Close()
			for _, entry := range registry.entries[:registry.used] {
				if err := entry.trust.DestroyEnvironment(); err != nil {
					t.Error(err)
				}
			}
			if err := registry.DestroyEnvironment(); err != nil {
				t.Error(err)
			}
		})
	}
	var durable func(*onlineBootstrapFixture, NamespaceBootstrapLimits) NamespaceDurabilityConfig
	if profile == DurableRestore {
		durable = func(f *onlineBootstrapFixture, l NamespaceBootstrapLimits) NamespaceDurabilityConfig {
			scope := NamespaceContinuityScope{Tenant: f.owner.root.Tenant, Authority: f.owner.root.Authority, Capacity: f.namespace.rules.capacityDigest, Limits: NamespaceContinuityLimits{TrustConfigurations: f.owner.limits.Configurations, TrustConfigBytes: uint32(f.owner.limits.ConfigBytes), StateBytes: f.namespace.rules.stateBytes, FetchDurationMS: l.FetchDurationMS, FetchAttempts: l.FetchAttempts}}
			cost, err := NamespaceDurabilityCharge(scope.Limits)
			if err != nil {
				t.Fatal(err)
			}
			dep := f.namespace.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
			borrow, err := dep.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			return NamespaceDurabilityConfig{Scope: scope, Store: &namespaceMemoryHistory{scope: scope}, Reservation: f.namespace.reserve(t, cost), Dependencies: borrow}
		}
	}
	f := onlineBootstrapConfigured(t, durable, append(prepare, setup)...)
	return f, registry
}

func registryAnchor(t *testing.T, f *onlineBootstrapFixture, authority string) *NamespaceTrustStore {
	t.Helper()
	root := f.owner.root
	root.Authority = authority
	cost, _ := NamespaceTrustCharge(f.owner.limits)
	dep := f.namespace.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	borrow, err := dep.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewNamespaceTrustAnchor(root, f.owner.limits, f.owner.clock, f.namespace.reserve(t, cost), borrow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		trust.Close()
		trust.mu.Lock()
		registered := trust.registry != nil
		trust.mu.Unlock()
		// A published anchor belongs to the registry teardown order. Its
		// retained history must remain protected until the registry and shared
		// resources have been closed; an unpublished anchor can be destroyed
		// directly here.
		if !registered {
			if err := trust.DestroyEnvironment(); err != nil {
				t.Error(err)
			}
		}
	})
	return trust
}

func TestNamespaceRegistryOriginalStartupAndProfile(t *testing.T) {
	for _, profile := range []VerificationContinuity{OnlineBootstrap, DurableRestore} {
		t.Run(map[VerificationContinuity]string{OnlineBootstrap: "online", DurableRestore: "durable"}[profile], func(t *testing.T) {
			f, r := registryFixture(t, profile, 1)
			if got, err := r.Lookup("tenant-1", "revocation-1"); err != nil || got != f.owner {
				t.Fatal("lookup changed original anchor", err)
			}
			if err := r.Register(f.owner); err != nil || r.used != 1 {
				t.Fatal("idempotent registration consumed history capacity", err)
			}
			if _, err := f.owner.Rules(); err == nil {
				t.Fatal("registered root alone authorized credentials")
			}
			n, err := f.operation.Run(context.Background(), f.provider)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.CheckNamespace(n); err != nil {
				t.Fatal("actual original bootstrap was not accepted", err)
			}
			before := f.namespace.resources.Snapshot()
			for range 16 {
				if err := r.CheckNamespace(n); err != nil {
					t.Fatal(err)
				}
			}
			if f.namespace.resources.Snapshot() != before {
				t.Fatal("registry checks allocated additional State/history")
			}
			if err := r.DestroyEnvironment(); err == nil {
				t.Fatal("live registry discarded history")
			}
			r.Close()
			if err := r.CheckNamespace(n); err == nil || f.owner.Head(NamespaceHeadTrust{}) == nil {
				t.Fatal("registry closure left authority open")
			}
			if r.used != 1 || f.namespace.resources.Snapshot().Charged != before.Charged {
				t.Fatal("logical close refunded retained history")
			}
		})
	}
}

func TestNamespaceRegistryRejectsSplitOwnersAndPrivateRoots(t *testing.T) {
	f, r := registryFixture(t, OnlineBootstrap, 2)
	duplicate := registryAnchor(t, f, "revocation-1")
	if err := r.Register(duplicate); err != CBORFailure("revocation_namespace_binding") {
		t.Fatal("second same-namespace anchor accepted", err)
	}
	c := NamespaceRegistryConfig{Continuity: OnlineBootstrap, Entries: 1, RuntimeBytes: 4096}
	cost, _ := NamespaceRegistryCharge(c)
	if _, err := NewNamespaceRegistry(c, f.namespace.reserve(t, cost)); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("physical Environment split into duplicate registries", err)
	}
	other := onlineBootstrap(t)
	if err := r.Register(other.owner); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("same labels admitted a different budget root", err)
	}
	f.owner.Close()
	if err := r.Register(duplicate); err != CBORFailure("revocation_namespace_binding") || r.used != 1 {
		t.Fatal("closing original owner erased its fixed slot", err)
	}
}

func TestNamespaceRegistryCapacityAndConcurrentRegistration(t *testing.T) {
	f, r := registryFixture(t, OnlineBootstrap, 2)
	a, b := registryAnchor(t, f, "other-authority"), registryAnchor(t, f, "other-authority")
	var wg sync.WaitGroup
	var result [2]error
	for i, anchor := range []*NamespaceTrustStore{a, b} {
		wg.Go(func() { result[i] = r.Register(anchor) })
	}
	wg.Wait()
	if (result[0] == nil) == (result[1] == nil) || r.used != 2 {
		t.Fatal("registration had zero or multiple winners", result)
	}
	third := registryAnchor(t, f, "third-authority")
	if err := r.Register(third); err != CBORFailure("configuration_capacity") {
		t.Fatal("full history table evicted existing namespace", err)
	}
	if third.registry != nil || r.used != 2 {
		t.Fatal("failed registration mutated original owners")
	}
}

func TestNamespaceRegistryProfileCheckedBeforeRecoveryStore(t *testing.T) {
	f, r := registryFixture(t, OnlineBootstrap, 2)
	target := registryAnchor(t, f, "second-authority")
	if err := r.Register(target); err != nil {
		t.Fatal(err)
	}
	// Invalid store inputs must not be consulted: the immutable profile gate
	// precedes store-scope checks, buffer transfer and provider work.
	if _, err := RestoreNamespace(context.Background(), context.Background(), target, NamespaceDurabilityConfig{}, 8, f.namespace.namespaceAllocation(t)); err != CBORFailure("revocation_continuity_binding") {
		t.Fatal("online profile reached durable recovery", err)
	}
	if target.bootstrapStarted {
		t.Fatal("wrong-profile call consumed original startup position")
	}
	g, durable := registryFixture(t, DurableRestore, 2)
	anchor := registryAnchor(t, g, "second-authority")
	if err := durable.Register(anchor); err != nil {
		t.Fatal(err)
	}
	limits := g.operation.limits
	cost, _ := NamespaceBootstrapCharge(limits)
	ref := g.namespace.reserve(t, cost)
	if _, err := NewNamespaceOnlineBootstrap(context.Background(), anchor, limits, g.namespace.namespaceAllocation(t), ref); err != CBORFailure("revocation_continuity_binding") {
		t.Fatal("durable profile silently fell back to live-only", err)
	}
	if err := ref.Check(); err != nil || anchor.bootstrapStarted {
		t.Fatal("profile refusal consumed startup allocation", err)
	}
}

func TestNamespaceRegistryRefusesRegistrationAfterStartup(t *testing.T) {
	f := onlineBootstrap(t)
	c := NamespaceRegistryConfig{Continuity: OnlineBootstrap, Entries: 1, RuntimeBytes: 4096}
	cost, _ := NamespaceRegistryCharge(c)
	r, err := NewNamespaceRegistry(c, f.namespace.reserve(t, cost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		f.namespace.resources.Close()
		if err := r.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	if err := r.Register(f.owner); err != CBORFailure("revocation_namespace_owner") || r.used != 0 {
		t.Fatal("startup work acquired registry history capacity afterwards", err)
	}
}
