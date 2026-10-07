package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type notifyStalledSink struct{}

func (*notifyStalledSink) TryAcceptNotify(context.Context, []byte) (uint64, error) {
	return 0, rpcv4.ErrCapacity
}
func (*notifyStalledSink) Published(uint64) (bool, error) { return false, nil }
func (*notifyStalledSink) NotifyTailReleased(uint64) bool { return true }
func (*notifyStalledSink) Wake() <-chan struct{}          { return nil }

type notifyRuntimeTestGuard struct{ ref resourcev4.Reference }

func (g notifyRuntimeTestGuard) WithNotifyPublication(_ protocolv4.ApplicationHeader, action func(resourcev4.Reference) error) error {
	return action(g.ref)
}

func TestNotifyPublisherRuntimeExpiresWithoutProviderWake(t *testing.T) {
	f, _, _ := rpcServicesPlanFixture(t)
	clock := sessionTestClock(t)
	config := rpcv4.NotifyPublisherConfig{Pending: 1, RuntimeBytes: 4096}
	charge, _ := rpcv4.NotifyPublisherCharge(config)
	ref := f.reserve(t, 1, charge)
	p, err := rpcv4.NewNotifyPublisher(&notifyStalledSink{}, config, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		p.Close()
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	}()
	charge, _ = NotifyChannelCharge(4096)
	owner := f.reserve(t, 1, charge)
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	deadline, err := timev4.NewAge(clock, 50, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	var header [512]byte
	n, _, err := codec.Encode(header[:], "observation_notify", protocolv4.ApplicationHeaderFields{Type: 42, ServiceContractDigest: [32]byte{7}, DeadlineAtMS: deadline.Cap()})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := rpcv4.NotifySourceCharge(0, 4096)
	b, _ := rpcv4.NotifySubmissionCharge(4096)
	s, err := p.Submit(context.Background(), header[:n], nil, deadline, notifyRuntimeTestGuard{owner}, f.reserve(t, 1, a), f.reserve(t, 1, b), 4096)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (&NotifyChannel{}).publish(ctx, p, &RPCBatchWriter{wake: make(chan struct{}, 1)}) }()
	select {
	case <-s.Done():
	case <-ctx.Done():
		t.Fatal("deadline required an unrelated provider wake", ctx.Err())
	}
	cancel()
	<-done
	if status := s.Progress(); status.HeaderAccepted || status.Reason != "deadline_exceeded" {
		t.Fatal("stalled notification expiry", status)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyPeerEOFPreservesAcceptedOutputTail(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := notificationRuntimeFixture(t)
	policy := authorizeNotificationRuntime(t, services[0], fixtures[0])
	authorizeNotificationRuntime(t, services[1], fixtures[1])
	observed := make(chan string, 1)
	subscription, err := services[1].notifications.Subscribe(0, NotificationDropNewest, notificationStrings(func(_ context.Context, value string) error {
		observed <- value
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		subscription.Close()
		until := time.Now().Add(3 * time.Second)
		for !subscription.Status().CleanupComplete && time.Now().Before(until) {
			services[1].notifications.Advance()
			runtime.Gosched()
		}
		if err := subscription.Release(); err != nil {
			t.Error(err)
		}
	})
	channel, err := services[0].OpenNotifyChannel(ctx, streamTestDeadline(t, endpoints[0].engine))
	if err != nil {
		t.Fatal(err)
	}
	var peer *NotifyChannel
	for peer == nil {
		services[1].mu.Lock()
		job := services[1].notifyChannels[0]
		if job != nil {
			peer = job.channel
		}
		services[1].mu.Unlock()
		if peer != nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("peer notification owner was not published", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	writer := channel.owner.flow.send.writer
	writer.mu.Lock()
	held := &nativeDelayedWriter{destination: writer.writer, entered: make(chan struct{}), returned: make(chan struct{})}
	writer.writer = held
	writer.mu.Unlock()
	released := false
	defer func() {
		if !released {
			close(held.returned)
		}
	}()
	payload := []byte("accepted output survives peer EOF")
	deadline, err := timev4.NewAge(services[0].clock, 5000, endpoints[0].engine.SessionParameters().SessionNotAfterMS)
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	var header [512]byte
	n, _, err := codec.Encode(header[:], "observation_notify", protocolv4.ApplicationHeaderFields{Type: policy.Type, ServiceContractDigest: policy.Digest, PayloadBytes: uint32(len(payload)), DeadlineAtMS: deadline.Cap()})
	if err != nil {
		t.Fatal(err)
	}
	submission, err := services[0].BeginObservationNotify(ctx, header[:n], payload, deadline)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal("notification was not submitted to the original provider", ctx.Err())
	}
	if err := peer.owner.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-channel.readerEnded:
	case <-ctx.Done():
		t.Fatal("peer EOF did not end the reader", ctx.Err())
	}
	select {
	case <-channel.done:
		t.Fatal("peer EOF canceled the accepted provider tail")
	default:
	}
	if channel.availablePublisher() != nil {
		t.Fatal("ended channel admitted another notification")
	}
	close(held.returned)
	released = true
	for {
		services[1].notifications.Advance()
		select {
		case value := <-observed:
			if value != string(payload) {
				t.Fatal("accepted notification changed", value)
			}
			goto delivered
		case <-ctx.Done():
			t.Fatal("accepted notification lost after peer EOF", ctx.Err())
		default:
			runtime.Gosched()
		}
	}
delivered:
	select {
	case <-submission.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := submission.Release(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-channel.done:
	case <-ctx.Done():
		t.Fatal("channel did not finish after its original publication", ctx.Err())
	}
}

func TestNotifyChannelsOpenAtSaturatedRootWithoutBusinessCapacity(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	var holds [2]resourcev4.Reference
	defer func() {
		for _, h := range holds {
			h.Release()
		}
	}()
	for role, f := range fixtures {
		s := f.root.Snapshot()
		var spare resourcev4.Vector
		for i := range spare {
			spare[i] = s.Limit[i] - s.Charged[i]
		}
		holds[role] = f.reserve(t, 1, spare)
	}
	for role, r := range services {
		deadline := streamTestDeadline(t, endpoints[role].engine)
		before := fixtures[role].root.Snapshot()
		if _, err := r.OpenNotifyChannel(ctx, deadline); err != nil {
			t.Fatal("notify OPEN needed fresh root budget", role, err)
		}
		if _, err := r.OpenNotifyChannel(ctx, deadline); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("duplicate opener notification channel", err)
		}
		if after := fixtures[role].root.Snapshot(); after.Charged != before.Charged || after.Reservations != before.Reservations {
			t.Fatal("notification channel escaped original admission", before, after)
		}
	}
	for _, e := range endpoints {
		if u := e.admission.Usage(); u.Active != 3 || u.Opening != 0 || u.Pending != 0 {
			t.Fatal("notify channels are not real internal streams", u)
		}
		e.admission.mu.Lock()
		business := e.admission.byOpener[0][BusinessStream] + e.admission.byOpener[1][BusinessStream]
		e.admission.mu.Unlock()
		if business != 0 {
			t.Fatal("notification OPEN consumed business capacity")
		}
	}
}

func TestNotifyBindingInitializationSharesOriginalChannelAtCapacity(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	var holds [2]resourcev4.Reference
	defer func() {
		for _, hold := range holds {
			hold.Release()
		}
	}()
	var before [2]resourcev4.Snapshot
	for role, fixture := range fixtures {
		snapshot := fixture.root.Snapshot()
		var spare resourcev4.Vector
		for i := range spare {
			spare[i] = snapshot.Limit[i] - snapshot.Charged[i]
		}
		holds[role] = fixture.reserve(t, 1, spare)
		before[role] = fixture.root.Snapshot()
	}
	initialization, cancel := context.WithCancel(ctx)
	defer cancel()
	r := services[0]
	deadline := streamTestDeadline(t, endpoints[0].engine)
	results := make(chan error, 8)
	for range cap(results) {
		go func() { results <- r.prepareBindingNotifyChannel(initialization, deadline) }()
	}
	for range cap(results) {
		if err := <-results; err != nil {
			t.Fatal("binding initialization", err)
		}
	}
	cancel()
	for role, fixture := range fixtures {
		after := fixture.root.Snapshot()
		if after.Charged != before[role].Charged || after.Reservations != before[role].Reservations {
			t.Fatal("binding initialization allocated outside the admitted channel", before[role], after)
		}
		if usage := endpoints[role].admission.Usage(); usage.Active != 2 || usage.Opening != 0 || usage.Pending != 0 {
			t.Fatal("concurrent bindings opened duplicate channels", usage)
		}
	}
	r.mu.Lock()
	job := r.notifyChannels[0]
	live := job != nil && job.context.Err() == nil && job.channel.availablePublisher() != nil
	r.mu.Unlock()
	if !live {
		t.Fatal("completed initialization retained the caller's canceled lifetime")
	}
	if err := r.prepareBindingNotifyChannel(ctx, deadline); err != nil {
		t.Fatal("later binding could not reuse the same accepted channel", err)
	}
	if _, err := r.OpenNotifyChannel(ctx, deadline); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("original opener position was not retained", err)
	}
}

func TestNotifyBindingWaitsForOriginalBootstrap(t *testing.T) {
	result := make(chan error, 1)
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeProfilePrepared(t, "services", nil,
		func(ctx context.Context, services [2]*RPCServices, endpoints [2]*bootstrapEndpoint) {
			r := services[0]
			deadline := streamTestDeadline(t, endpoints[0].engine)
			observer, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			if err := r.prepareBindingNotifyChannel(observer, deadline); !errors.Is(err, context.DeadlineExceeded) {
				t.Error("bootstrap wait lost caller cancellation", err)
			}
			cancel()
			sample, err := endpoints[0].engine.Clock().Sample()
			if err != nil {
				t.Fatal(err)
			}
			// Keep the deadline representable beyond the fixture's trusted
			// uncertainty interval, with only a short remaining wait.
			short, err := timev4.NewAgeAt(endpoints[0].engine.Clock(), sample, sample.UpperMS-sample.LowerMS+25, ^uint64(0))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.prepareBindingNotifyChannel(ctx, short); !errors.Is(err, timev4.ErrExpired) {
				t.Error("bootstrap wait lost the original admission deadline", err)
			}
			go func() { result <- r.prepareBindingNotifyChannel(ctx, deadline) }()
			select {
			case err := <-result:
				t.Error("binding returned before the admitted bootstrap started", err)
				result <- err
			case <-time.After(20 * time.Millisecond):
			}
		})
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("binding did not join original initialization", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := services[0].prepareBindingNotifyChannel(ctx, streamTestDeadline(t, endpoints[0].engine)); err != nil {
		t.Fatal("binding could not reuse its original channel", err)
	}
	for _, endpoint := range endpoints {
		if usage := endpoint.admission.Usage(); usage.Active != 2 || usage.Opening != 0 || usage.Pending != 0 {
			t.Fatal("bootstrap wait created extra channels", usage)
		}
	}
}

func TestNotifyBindingCanceledWaitDoesNotCancelSharedOpening(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	r.mu.Lock()
	job, err := r.reserveNotifyChannelLocked(ctx, protocolv4.ClientToServer)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	deadline := streamTestDeadline(t, endpoints[0].engine)
	waiter, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- r.prepareBindingNotifyChannel(waiter, deadline) }()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled binding waited for unrelated initialization", err)
	}
	if job.context.Err() != nil {
		t.Fatal("joining binding canceled the original opening")
	}
	go job.prepareDependency(deadline)
	if err := r.prepareBindingNotifyChannel(ctx, deadline); err != nil {
		t.Fatal("original channel did not finish after a joiner canceled", err)
	}
}

func TestNotifyChannelRejectsMetadataBeforeAcceptance(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	a, err := r.checkoutInternalChannel(8)
	if err != nil {
		t.Fatal(err)
	}
	defer a.release()
	a.stream.reservation.Writer = r.bootstrap.output
	spec, _ := protocolv4.Notify()
	h, _, err := endpoints[0].admission.OpenLocal(ctx, InternalStream, spec.Kind, []byte{1}, &CarrierAssociation{shared: r.bootstrap.admission.sharedIngress}, a.stream.reservation, streamTestDeadline(t, endpoints[0].engine))
	if err != nil {
		t.Fatal(err)
	}
	if err = h.owner.WaitOutcome(ctx, h); !errors.Is(err, ErrOpenRejected) {
		t.Fatal("notify accepted nonempty metadata", err)
	}
	if err = h.owner.CleanupStream(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err = h.owner.CarrierClosed(h); err != nil {
		t.Fatal(err)
	}
	services[1].mu.Lock()
	defer services[1].mu.Unlock()
	if services[1].notifyChannels != ([2]*notifyChannelOpening{}) {
		t.Fatal("rejected metadata installed notification runtime")
	}
}

func TestNotifyChannelRebuildWaitsForOriginalAlias(t *testing.T) {
	ctx, services, _, endpoints, _, _ := rpcChannelRuntimeFixture(t)
	r := services[0]
	deadline := streamTestDeadline(t, endpoints[0].engine)
	first, err := r.OpenNotifyChannel(ctx, deadline)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	job := r.notifyChannels[0]
	handle := job.handle
	r.mu.Unlock()
	first.owner.queue.mu.Lock()
	alias, err := first.owner.queue.reservation.Borrow()
	first.owner.queue.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	first.Close()
	select {
	case <-job.done:
		if job.cleanupError != nil {
			t.Fatal(job.cleanupError)
		}
	case <-ctx.Done():
		t.Fatal("notify channel did not clean up", ctx.Err())
	}
	if _, err = r.OpenNotifyChannel(ctx, deadline); !errors.Is(err, resourcev4.ErrCapacity) && !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("notify position reused while backing remained borrowed", err)
	}
	alias.Release()
	var next *NotifyChannel
	for {
		next, err = r.OpenNotifyChannel(ctx, deadline)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !errors.Is(err, resourcev4.ErrCapacity) && !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("notify rebuild", err, ctx.Err())
		}
		runtime.Gosched()
	}
	if next.Association() == first.Association() || next.owner.handle.scope <= handle.scope {
		t.Fatal("notify rebuild reused message identity")
	}
	if err = endpoints[0].engine.ApplicationReady(); err != nil {
		t.Fatal("notify closure ended healthy Session", err)
	}
}

func notificationRuntimeFixture(t *testing.T) (context.Context, [2]*RPCServices, [2]*executorFixture, [2]*bootstrapEndpoint, [2]*RPCChannel, [2][16]byte) {
	t.Helper()
	// Credentials, authority gates, Stream input and notification deadlines
	// share one actual clock, as they do in complete Session assembly.
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1250}); err != nil {
		t.Fatal(err)
	}
	return rpcChannelRuntimeProfile(t, "services", func(_ int, _ *executorFixture, _ *SessionPlan, c *RPCServicesConfig) {
		c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{initialFixture(t, "service_notify_observation")}}}
		c.NotificationMethods = []NotificationMethod{{Method: 0}}
	}, clock)
}

func authorizeNotificationRuntime(t *testing.T, r *RPCServices, f *executorFixture) protocolv4.ServiceContractPolicy {
	t.Helper()
	trust := newSessionAdmissionTrustProfile(t, f.root, f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}), r.owner, "live_authority", "transport", r.clock)
	a, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(nil) })
	policy, err := r.routes.RegisteredMethodPolicy(0)
	if err != nil {
		t.Fatal(err)
	}
	p := r.plan
	p.config.AuthorizeApplication = func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		l, err := c.ReserveLease(c.Binding(), nil, func(context.Context) error { return nil })
		if err == nil {
			err = l.SetNotificationAccess(policy.Namespace, policy.Type, true)
		}
		return AuthorizeApplicationResult{Lease: l}, err
	}
	p.claimed = true
	if err = p.authorize(context.Background(), ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt}, a.Check); err != nil {
		t.Fatal(err)
	}
	if err = p.lease.bindAuthorization(a); err != nil {
		t.Fatal(err)
	}
	r.notifications.activate()
	return policy
}

func TestNotifyChannelDuplexObservationAndCurrentSenderAuthorization(t *testing.T) {
	ctx, services, fixtures, endpoints, _, _ := notificationRuntimeFixture(t)
	var policies [2]protocolv4.ServiceContractPolicy
	var observed [2]chan string
	for role, r := range services {
		policies[role] = authorizeNotificationRuntime(t, r, fixtures[role])
		observed[role] = make(chan string, 2)
		s, err := r.notifications.Subscribe(0, NotificationDropNewest, notificationStrings(func(_ context.Context, value string) error {
			observed[role] <- value
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			s.Close()
			end := time.Now().Add(3 * time.Second)
			for !s.Status().CleanupComplete && time.Now().Before(end) {
				r.notifications.Advance()
				runtime.Gosched()
			}
			if err := s.Release(); err != nil {
				t.Error(err)
			}
		})
		if _, err = r.OpenNotifyChannel(ctx, streamTestDeadline(t, endpoints[role].engine)); err != nil {
			t.Fatal(err)
		}
	}
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	for role, r := range services {
		payload := bytes.Repeat([]byte{byte('a' + role)}, 40000)
		deadline, err := timev4.NewAge(r.clock, 5000, endpoints[role].engine.SessionParameters().SessionNotAfterMS)
		if err != nil {
			t.Fatal(err)
		}
		var header [512]byte
		n, _, err := codec.Encode(header[:], "observation_notify", protocolv4.ApplicationHeaderFields{Type: policies[role].Type, ServiceContractDigest: policies[role].Digest, PayloadBytes: uint32(len(payload)), DeadlineAtMS: deadline.Cap()})
		if err != nil {
			t.Fatal(err)
		}
		before := r.network.Snapshot()
		s, err := r.BeginObservationNotify(ctx, header[:n], payload, deadline)
		if err != nil {
			t.Fatal("authorized notification", role, err)
		}
		t.Cleanup(func() {
			if err := s.Release(); err != nil {
				t.Error(err)
			}
		})
		for {
			services[1-role].notifications.Advance()
			select {
			case value := <-observed[1-role]:
				if value != string(payload) {
					t.Fatal("duplex notification payload changed")
				}
				goto received
			case <-ctx.Done():
				t.Fatal("notification did not reach observer", ctx.Err())
			default:
				runtime.Gosched()
			}
		}
	received:
		select {
		case <-s.Done():
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if after := r.network.Snapshot(); after != before {
			t.Fatal("notification consumed RPC response or network ownership", before, after)
		}
		if err = r.plan.lease.SetNotificationAccess(policies[role].Namespace, policies[role].Type, false); err != nil {
			t.Fatal(err)
		}
		if _, err = r.BeginObservationNotify(ctx, header[:n], payload, deadline); !errors.Is(err, ErrApplicationAuthorization) {
			t.Fatal("revoked sender submitted notification", err)
		}
		if err = r.plan.lease.SetNotificationAccess(policies[role].Namespace, policies[role].Type, true); err != nil {
			t.Fatal(err)
		}
		if err = r.routes.SetRegistered(policies[role].Digest, false); err != nil {
			t.Fatal(err)
		}
		if _, err = r.BeginObservationNotify(ctx, header[:n], payload, deadline); !errors.Is(err, rpcv4.ErrMethod) {
			t.Fatal("unregistered sender submitted notification", err)
		}
		if err = r.routes.SetRegistered(policies[role].Digest, true); err != nil {
			t.Fatal(err)
		}
	}
}
