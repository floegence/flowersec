package protocolv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type bootstrapTestProvider struct {
	query func(context.Context, NamespaceBootstrapRequest, []byte) (int, error)
	fetch NamespaceFetch
}

func (p bootstrapTestProvider) Query(c context.Context, r NamespaceBootstrapRequest, b []byte) (int, error) {
	return p.query(c, r, b)
}
func (p bootstrapTestProvider) Fetch(c context.Context, r NamespaceContent, b []byte) (int, error) {
	return p.fetch(c, r, b)
}

type onlineBootstrapFixture struct {
	*independentTrustFixture
	operation *NamespaceOnlineBootstrap
	provider  bootstrapTestProvider
	head      *NamespaceHead
	state     []byte
	tick      *atomic.Uint64
	alter     func(*cborRefValue)
}

func onlineBootstrap(t *testing.T) *onlineBootstrapFixture {
	t.Helper()
	n := newNamespaceFixture(t)
	f := &onlineBootstrapFixture{independentTrustFixture: &independentTrustFixture{namespace: n, config: n.seed(t, "trust_config_fields"), seed: [32]byte{71, 23, 4}}}
	clock, tick := namespaceClockFixture(t, n, false)
	f.tick = tick
	// The independently signed config names the actual production Head key,
	// immutable mapping and State used by this authority fixture.
	capacity, _, err := n.r.decode(n.capacity, "NamespaceCapacity", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, "capacity", capacity)
	issuers := oracleField(t, n.r.cborReference, "TrustConfig", f.config, "issuer_authorizations")
	for _, issuer := range issuers.items {
		n.set(t, "CredentialIssuerAuthorization", issuer, "namespace_capacity_digest", namespaceBytes(n.rules.capacityDigest[:]))
	}
	d, _, err := n.r.decode(n.delegation, "HeadSignerDelegation", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, "head_delegations", namespaceArray(d))
	f.head, f.state = n.bindHead(t, 1, [2]uint64{})
	limits := NamespaceTrustLimits{Configurations: 4, ConfigBytes: 32768, MapNodes: 8192, RuntimeBytes: 65536}
	charge, err := NamespaceTrustCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	dependency := n.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096})
	borrow, err := dependency.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = NewNamespaceTrustAnchor(NamespaceTrustRoot{Tenant: "tenant-1", Authority: "revocation-1", KeyID: [16]byte(bytes.Repeat([]byte{0x71}, 16)), PublicKey: testTrustPublic(f.seed), MaxLifetimeMS: 10000}, limits, clock, n.reserve(t, charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.owner.Close()
		if f.owner.namespace != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := f.owner.namespace.WaitCleanup(ctx); err != nil {
				t.Error(err)
			}
		}
		n.resources.Close()
		if err := f.owner.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	bl := NamespaceBootstrapLimits{ResponseBytes: 32768, ResponseNodes: 8192, StateBytes: 4096, DurationMS: 4000, FetchDurationMS: 4000, FetchAttempts: 2, Subscribers: 8, RuntimeBytes: 65536}
	cost, err := NamespaceBootstrapCharge(bl)
	if err != nil {
		t.Fatal(err)
	}
	f.operation, err = NewNamespaceOnlineBootstrap(context.Background(), f.owner, bl, n.namespaceAllocation(t), n.reserve(t, cost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.operation.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.operation.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := f.operation.Retire(); err != nil {
			t.Error(err)
		}
	})
	f.provider.query = func(_ context.Context, r NamespaceBootstrapRequest, out []byte) (int, error) {
		if r.Nonce == ([32]byte{}) || r.Tenant != "tenant-1" || r.Authority != "revocation-1" {
			t.Fatal("missing original nonce or namespace")
		}
		config := f.wire(t)
		value, err := n.r.namedMap("TrustBootstrapResponse", map[string]*cborRefValue{
			"schema_revision": {major: 3, data: []byte("4")}, "tenant_id": {major: 3, data: []byte(r.Tenant)}, "revocation_authority_id": {major: 3, data: []byte(r.Authority)},
			"request_nonce": namespaceBytes(r.Nonce[:]), "issued_at_ms": namespaceNumber(1000), "not_after_ms": namespaceNumber(5000),
			"trust_config": namespaceBytes(config), "freshness_head": namespaceBytes(f.head.bytes), "signing_key_id": namespaceBytes(f.owner.root.KeyID[:]), "signature": namespaceBytes(make([]byte, 64)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if f.alter != nil {
			f.alter(value)
		}
		signed := signRuntimeFixture(t, "TrustBootstrapResponse", value.encode(nil), DecodeContext{})
		wire, err := signed.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return copy(out, wire), nil
	}
	f.provider.fetch = func(_ context.Context, key NamespaceContent, out []byte) (int, error) {
		if key.Digest != f.head.stateDigest || key.EncodedBytes != uint64(len(f.state)) || len(out) != len(f.state) || cap(out) != len(out) {
			t.Fatal("content read not fixed to original Head")
		}
		return copy(out, f.state), nil
	}
	return f
}

func TestNamespaceOnlineBootstrapOriginalPairAndDelivery(t *testing.T) {
	f := onlineBootstrap(t)
	if _, err := f.owner.Rules(); err == nil {
		t.Fatal("root alone granted trust")
	}
	ctx, cancel := context.WithCancel(context.Background())
	n, err := f.operation.Run(ctx, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if n != f.owner.namespace || n.active.head.digest != f.head.digest || !bytes.Equal(n.active.document.Bytes(), f.state) {
		t.Fatal("delivered different original pair")
	}
	if err := n.Observe(n.observed); err != nil {
		t.Fatal("delivered namespace still owned by wait cancellation", err)
	}
	if err := f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	if f.owner.bootstrap || !f.owner.bootstrapStarted {
		t.Fatal("lost original startup ownership")
	}
	if _, err := f.operation.Run(context.Background(), f.provider); err == nil {
		t.Fatal("bootstrap operation replayed")
	}
	if err := f.owner.DestroyEnvironment(); err == nil {
		t.Fatal("ordinary retirement erased live history")
	}
}

func TestNamespaceOnlineBootstrapRejectsWrongOriginalBinding(t *testing.T) {
	for _, attack := range []string{"nonce", "tenant", "key_id", "config_signature", "head_signature", "head_key", "state", "response_expiry", "late_trust"} {
		t.Run(attack, func(t *testing.T) {
			f := onlineBootstrap(t)
			reads := 0
			fetch := f.provider.fetch
			f.provider.fetch = func(c context.Context, key NamespaceContent, out []byte) (int, error) {
				reads++
				n, err := fetch(c, key, out)
				if attack == "state" {
					out[len(out)-1] ^= 1
				}
				if attack == "late_trust" {
					f.owner.Close()
				}
				return n, err
			}
			f.alter = func(v *cborRefValue) {
				n := f.namespace
				set := func(name string, value *cborRefValue) { n.set(t, "TrustBootstrapResponse", v, name, value) }
				switch attack {
				case "nonce":
					set("request_nonce", namespaceBytes(make([]byte, 32)))
				case "tenant":
					set("tenant_id", &cborRefValue{major: 3, data: []byte("other")})
				case "key_id":
					set("signing_key_id", namespaceBytes(make([]byte, 16)))
				case "config_signature", "head_signature":
					name := "trust_config"
					if attack == "head_signature" {
						name = "freshness_head"
					}
					field := oracleField(t, n.r.cborReference, "TrustBootstrapResponse", v, name)
					field.data[len(field.data)-1] ^= 1
				case "head_key":
					delegation := oracleField(t, n.r.cborReference, "TrustConfig", f.config, "head_delegations").items[0]
					key := testTrustPublic([32]byte{82})
					n.set(t, "HeadSignerDelegation", delegation, "signer_public_key", namespaceBytes(key[:]))
					set("trust_config", namespaceBytes(f.wire(t)))
				case "response_expiry":
					set("not_after_ms", namespaceNumber(1200))
				}
			}
			n, err := f.operation.Run(context.Background(), f.provider)
			if err == nil || n != nil {
				t.Fatal("invalid bootstrap published", attack)
			}
			if attack != "state" && attack != "late_trust" && reads != 0 {
				t.Fatal("content fetched before independent original binding")
			}
		})
	}
}

func TestNamespaceOnlineBootstrapRetainsCanceledProviderTail(t *testing.T) {
	for _, stage := range []string{"query", "fetch"} {
		t.Run(stage, func(t *testing.T) {
			f := onlineBootstrap(t)
			entered, release := make(chan struct{}), make(chan struct{})
			if stage == "query" {
				f.provider.query = func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
					close(entered)
					<-release
					return 0, nil
				}
			} else {
				fetch := f.provider.fetch
				f.provider.fetch = func(c context.Context, k NamespaceContent, out []byte) (int, error) {
					close(entered)
					<-release
					return fetch(c, k, out)
				}
			}
			done := make(chan error, 1)
			go func() { _, err := f.operation.Run(context.Background(), f.provider); done <- err }()
			<-entered
			before := f.namespace.resources.Snapshot().Charged
			f.operation.Close()
			if err := f.operation.Retire(); err == nil || !f.owner.bootstrap {
				t.Fatal("live provider tail retired")
			}
			if f.namespace.resources.Snapshot().Charged != before {
				t.Fatal("cancellation returned provider charge")
			}
			select {
			case <-done:
				t.Fatal("cancellation pretended provider had returned")
			default:
			}
			close(release)
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal("late result was published", err)
			}
			if f.owner.namespace != nil {
				t.Fatal("late startup installed namespace")
			}
		})
	}
}

func TestNamespaceOnlineBootstrapAbnormalFetchReturnsOriginalReservations(t *testing.T) {
	for _, mode := range []string{"panic", "goexit", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := onlineBootstrap(t)
			before := f.namespace.resources.Snapshot().Reservations
			f.provider.fetch = func(context.Context, NamespaceContent, []byte) (int, error) {
				switch mode {
				case "panic":
					panic("provider")
				case "goexit":
					runtime.Goexit()
				case "expired":
					f.tick.Store(4000)
				}
				return 0, nil
			}
			exited := make(chan struct{})
			go func() {
				defer close(exited)
				if n, err := f.operation.Run(context.Background(), f.provider); err == nil || n != nil {
					t.Error("abnormal provider published")
				}
			}()
			<-exited
			if err := f.operation.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if mode == "expired" && !errors.Is(f.operation.terminal, timev4.ErrExpired) {
				t.Fatal(f.operation.terminal)
			}
			if f.namespace.resources.Snapshot().Reservations != before {
				t.Fatal("abnormal provider lost reserved namespace backings")
			}
		})
	}
}
