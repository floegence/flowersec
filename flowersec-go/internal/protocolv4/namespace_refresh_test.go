package protocolv4

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type refreshTestProvider struct {
	trust, head func(context.Context, NamespaceRefreshRequest, []byte) (int, error)
	fetch       NamespaceFetch
}

func (p refreshTestProvider) Trust(c context.Context, r NamespaceRefreshRequest, b []byte) (int, error) {
	return p.trust(c, r, b)
}
func (p refreshTestProvider) Head(c context.Context, r NamespaceRefreshRequest, b []byte) (int, error) {
	return p.head(c, r, b)
}
func (p refreshTestProvider) Fetch(c context.Context, r NamespaceContent, b []byte) (int, error) {
	return p.fetch(c, r, b)
}

func newRefreshFixture(t *testing.T) (*onlineBootstrapFixture, *NamespaceRefresh, refreshTestProvider) {
	t.Helper()
	f := onlineBootstrap(t)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	l := NamespaceRefreshLimits{HeadIntervalMS: 10, TrustIntervalMS: 1000, DurationMS: 500, RuntimeBytes: 65536}
	charge, err := NamespaceRefreshCharge(l, f.owner.limits.ConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewNamespaceRefresh(n, f.owner, l, f.namespace.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := r.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := r.Retire(); err != nil {
			t.Error(err)
		}
	})
	config := f.wire(t)
	p := refreshTestProvider{
		trust: func(_ context.Context, req NamespaceRefreshRequest, out []byte) (int, error) {
			if req.Tenant != "tenant-1" || req.Authority != "revocation-1" {
				t.Error("refresh selected another namespace")
			}
			return copy(out, config), nil
		},
		head: func(_ context.Context, _ NamespaceRefreshRequest, out []byte) (int, error) {
			return copy(out, f.head.bytes), nil
		},
		fetch: f.provider.fetch,
	}
	return f, r, p
}

func waitRefresh(t *testing.T, r *NamespaceRefresh, count uint64) error {
	t.Helper()
	end := time.NewTimer(3 * time.Second)
	defer end.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		completed, err := r.Status()
		if completed >= count {
			return err
		}
		select {
		case <-end.C:
			t.Fatal("original refresh did not complete")
		case <-tick.C:
		}
	}
}

func TestNamespaceRefreshReusesCompleteStateAndLimitsPushHints(t *testing.T) {
	f, r, p := newRefreshFixture(t)
	f.head, f.state = f.namespace.bindHead(t, 2, [2]uint64{})
	var heads, trusts atomic.Uint32
	readHead, readTrust := p.head, p.trust
	p.head = func(c context.Context, q NamespaceRefreshRequest, b []byte) (int, error) {
		heads.Add(1)
		return readHead(c, q, b)
	}
	p.trust = func(c context.Context, q NamespaceRefreshRequest, b []byte) (int, error) {
		trusts.Add(1)
		return readTrust(c, q, b)
	}
	p.fetch = func(context.Context, NamespaceContent, []byte) (int, error) {
		t.Error("unchanged complete content was downloaded again")
		return 0, errors.New("unexpected read")
	}
	if err := r.Start(p); err != nil {
		t.Fatal(err)
	}
	if err := waitRefresh(t, r, 1); err != nil {
		t.Fatal(err)
	}
	r.namespace.mu.Lock()
	sequence := r.namespace.active.head.sequence
	r.namespace.mu.Unlock()
	if sequence != 2 {
		t.Fatal("new Head was not paired with complete cached State", sequence)
	}
	for range 1000 {
		r.Request()
	}
	if heads.Load() != 1 || trusts.Load() != 1 {
		t.Fatal("push bypassed monotonic minimum delay")
	}
	f.tick.Add(20)
	r.Request()
	if err := waitRefresh(t, r, 2); err != nil {
		t.Fatal(err)
	}
	if heads.Load() != 2 || trusts.Load() != 1 {
		t.Fatal("separate refresh cadence changed", heads.Load(), trusts.Load())
	}
	if err := r.Start(p); err == nil {
		t.Fatal("second worker admitted")
	}
	charge, _ := NamespaceRefreshCharge(r.limits, f.owner.limits.ConfigBytes)
	if _, err := NewNamespaceRefresh(r.namespace, f.owner, r.limits, f.namespace.reserve(t, charge)); err == nil {
		t.Fatal("second namespace refresh owner admitted")
	}
}

func TestNamespaceRefreshKeepsOriginalContentAcrossNewerObservation(t *testing.T) {
	f, r, p := newRefreshFixture(t)
	installBootstrapIssuerDenial(t, f, bootstrapIssuerEvidence(t, f), 2)
	original := f.head
	state := append([]byte(nil), f.state...)
	entered, release := make(chan struct{}), make(chan struct{})
	var reads atomic.Uint32
	p.fetch = func(_ context.Context, key NamespaceContent, out []byte) (int, error) {
		reads.Add(1)
		if key.Digest != original.stateDigest || key.EncodedBytes != uint64(len(state)) {
			t.Error("original content changed")
		}
		close(entered)
		<-release
		return copy(out, state), nil
	}
	if err := r.Start(p); err != nil {
		t.Fatal(err)
	}
	<-entered
	newer, _ := f.namespace.bindHead(t, 3, [2]uint64{})
	// Use an independent verifier, as an authenticated push would, while the
	// service's original State provider is still running.
	limit, _ := SchemaByteLimit("FreshnessHead")
	decoder, _ := NewDecoder(limit, limit)
	codec, _ := NewSignedMapCodec("FreshnessHead", limit, limit)
	head, err := f.owner.bindHead(decoder, codec, nil, newer.bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.namespace.Observe(head); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := waitRefresh(t, r, 1); err != nil {
		t.Fatal(err)
	}
	r.namespace.mu.Lock()
	active, observed := r.namespace.active.head.sequence, r.namespace.observed.sequence
	r.namespace.mu.Unlock()
	if active != 2 || observed != 3 {
		t.Fatal("new observation canceled or replaced original", active, observed)
	}
	f.tick.Add(20)
	r.Request()
	if err := waitRefresh(t, r, 2); err != nil {
		t.Fatal(err)
	}
	r.namespace.mu.Lock()
	active = r.namespace.active.head.sequence
	r.namespace.mu.Unlock()
	if active != 3 || reads.Load() != 1 {
		t.Fatal("known newest Head was not completed from full cached State", active, reads.Load())
	}
}

func TestNamespaceRefreshCancellationRetainsActualProviderTail(t *testing.T) {
	for _, stage := range []string{"trust", "head", "state"} {
		t.Run(stage, func(t *testing.T) {
			f, r, p := newRefreshFixture(t)
			installBootstrapIssuerDenial(t, f, bootstrapIssuerEvidence(t, f), 2)
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			block := func(c context.Context) {
				close(entered)
				<-c.Done()
				close(canceled)
				<-release
			}
			switch stage {
			case "trust":
				read := p.trust
				p.trust = func(c context.Context, q NamespaceRefreshRequest, b []byte) (int, error) {
					block(c)
					return read(c, q, b)
				}
			case "head":
				read := p.head
				p.head = func(c context.Context, q NamespaceRefreshRequest, b []byte) (int, error) {
					block(c)
					return read(c, q, b)
				}
			case "state":
				read := p.fetch
				p.fetch = func(c context.Context, q NamespaceContent, b []byte) (int, error) { block(c); return read(c, q, b) }
			}
			if err := r.Start(p); err != nil {
				t.Fatal(err)
			}
			<-entered
			r.Close()
			<-canceled
			r.namespace.Close(nil)
			if r.namespace.CleanupComplete() {
				t.Fatal("namespace cleanup omitted its original refresh provider")
			}
			if err := r.Retire(); err == nil {
				t.Fatal("refunded actual provider tail")
			}
			select {
			case <-r.done:
				t.Fatal("cleanup completed before original callback")
			default:
			}
			close(release)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := r.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := r.namespace.WaitCleanup(ctx); err != nil {
				t.Fatal("namespace did not join original refresh tail", err)
			}
			if r.namespace.active.head.sequence != 1 {
				t.Fatal("canceled late pair was installed")
			}
		})
	}
}

func TestNamespaceRefreshAbnormalExitAndDeadline(t *testing.T) {
	for _, stage := range []string{"trust", "head", "state"} {
		for _, mode := range []string{"panic", "goexit", "deadline"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				f, r, p := newRefreshFixture(t)
				installBootstrapIssuerDenial(t, f, bootstrapIssuerEvidence(t, f), 2)
				enter := make(chan struct{})
				fail := func(c context.Context) (int, error) {
					close(enter)
					switch mode {
					case "panic":
						panic("original provider panic")
					case "goexit":
						runtime.Goexit()
					}
					<-c.Done()
					return 0, c.Err()
				}
				switch stage {
				case "trust":
					p.trust = func(c context.Context, _ NamespaceRefreshRequest, _ []byte) (int, error) { return fail(c) }
				case "head":
					p.head = func(c context.Context, _ NamespaceRefreshRequest, _ []byte) (int, error) { return fail(c) }
				case "state":
					p.fetch = func(c context.Context, _ NamespaceContent, _ []byte) (int, error) { return fail(c) }
				}
				if err := r.Start(p); err != nil {
					t.Fatal(err)
				}
				<-enter
				if mode == "deadline" {
					f.tick.Add(600)
					if err := waitRefresh(t, r, 1); err == nil {
						t.Fatal("deadline disappeared")
					}
					r.Close()
				} else if stage == "state" && mode == "panic" {
					// The original pin catches a panicking Fetch, settles that
					// content and lets the shared service continue at its cadence.
					if err := waitRefresh(t, r, 1); err == nil {
						t.Fatal("panic disappeared")
					}
					r.Close()
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := r.WaitCleanup(ctx); err != nil {
					t.Fatal(err)
				}
				_, err := r.Status()
				if err == nil {
					t.Fatal("abnormal provider outcome disappeared")
				}
				if r.namespace.active.head.sequence != 1 {
					t.Fatal("abnormal result published")
				}
			})
		}
	}
}

func TestNamespaceRefreshRejectsForgedHeadAndLateContent(t *testing.T) {
	for _, mode := range []string{"signature", "equivocation", "late_state", "signer_rejected"} {
		t.Run(mode, func(t *testing.T) {
			f, r, p := newRefreshFixture(t)
			installBootstrapIssuerDenial(t, f, bootstrapIssuerEvidence(t, f), 2)
			switch mode {
			case "signature":
				f.head.bytes[len(f.head.bytes)-1] ^= 1
			case "equivocation":
				f.head, f.state = f.namespace.bindHead(t, 1, [2]uint64{})
			case "late_state":
				read := p.fetch
				p.fetch = func(c context.Context, q NamespaceContent, b []byte) (int, error) {
					f.tick.Add(600) // Return before the watchdog's next host tick.
					return read(c, q, b)
				}
			case "signer_rejected":
				f.advance(t, 2, 6000)
				f.set(t, "rejected_head_signers", namespaceArray(namespaceBytes(f.head.signerID[:])))
				wire := f.wire(t)
				p.trust = func(_ context.Context, _ NamespaceRefreshRequest, out []byte) (int, error) {
					return copy(out, wire), nil
				}
			}
			if err := r.Start(p); err != nil {
				t.Fatal(err)
			}
			if err := waitRefresh(t, r, 1); err == nil {
				t.Fatal("invalid or expired original result accepted")
			}
			r.namespace.mu.Lock()
			active := r.namespace.active.head.sequence
			r.namespace.mu.Unlock()
			if active != 1 {
				t.Fatal("bad refresh replaced active state")
			}
		})
	}
}

func TestNamespaceRefreshTrustTransportFailurePreservesOriginalValidWork(t *testing.T) {
	f, r, p := newRefreshFixture(t)
	f.head, f.state = f.namespace.bindHead(t, 2, [2]uint64{})
	failure := errors.New("independent trust transport unavailable")
	p.trust = func(context.Context, NamespaceRefreshRequest, []byte) (int, error) { return 0, failure }
	if err := r.Start(p); err != nil {
		t.Fatal(err)
	}
	if err := waitRefresh(t, r, 1); err != failure {
		t.Fatal("trust failure was hidden", err)
	}
	r.namespace.mu.Lock()
	active := r.namespace.active.head.sequence
	r.namespace.mu.Unlock()
	if active != 2 {
		t.Fatal("valid original trust could not complete current Head", active)
	}
}
