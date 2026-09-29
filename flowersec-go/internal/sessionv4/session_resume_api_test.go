package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This is a client assembly fixture with real authenticated shared-carrier
// streams. The peer reads and replies explicitly; it does not qualify durable
// server token consumption, which belongs to the execution-store integration.
func resumeClientPair(t *testing.T) ([2]*SessionCore, [2]*StreamOwnership, ResumeMethodDefinition, protocolv4.ResumeToken, context.Context) {
	return resumeSessionPair(t, nil)
}

func resumeSessionPair(t *testing.T, live *resumeLiveServerFixture) ([2]*SessionCore, [2]*StreamOwnership, ResumeMethodDefinition, protocolv4.ResumeToken, context.Context) {
	t.Helper()
	body := initialFixture(t, "service_unary_restart")
	if live != nil {
		body = initialFixture(t, "service_unary_execution")
		if body[0] != 0xb3 || bytes.Count(body, []byte{0x15, 0xf4}) != 1 {
			t.Fatal("checkpoint fixture changed")
		}
		body = bytes.Replace(body, []byte{0x15, 0xf4}, []byte{0x14, 0x66, 'o', 'f', 'f', 's', 'e', 't', 0x15, 0xf4}, 1)
		body[0]++
	}
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.Policy()
	contract.Release()
	if err != nil {
		t.Fatal(err)
	}
	var sharedClock *timev4.Clock
	if live != nil && live.issueViaRPC {
		sharedClock, err = timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) { return timev4.Tick{Incarnation: [16]byte{1}}, nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sharedClock.Close)
		mark, err := sharedClock.Monotonic()
		if err != nil {
			t.Fatal(err)
		}
		if err := sharedClock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1250}); err != nil {
			t.Fatal(err)
		}
	}
	var fixtures [2]initialCoreFixture
	var executors [2]*executorFixture
	rolePreparing := 0
	prepare := initialCorePrepareWithResources(t, &fixtures, false, func(c *SessionCoreConfig) {
		c.applicationServices = true
		c.MaxScopes, c.WorkSlots = 16, 16
		c.Open.Active, c.Open.Terminal = 13, 32
		c.Open.PerClass = [3]uint32{2, 10, 1}
		c.Open.PerOpener = [2][3]uint32{{2, 5, 1}, {2, 5}}
		c.Open.Protected = [2][3]uint32{{0, 5, 1}, {0, 5}}
		c.Open.Lifetime = [2][3]uint64{{1024, 1024, 16}, {1024, 1024}}
		c.SendWorkers = [3]uint32{2, 10, 1}
		c.Streams = SessionStreamConfig{ReceivePoolBytes: 1 << 20, ReceiveBytes: 32768, InitialReceiveLimit: 16384, SendBytes: 1024, QueueBytes: 16384, RuntimeBytes: 4096, WriteWaiters: 2, MaxPlaintext: 1152, Chunk: 1024}
		if live != nil && rolePreparing == 1 {
			live.prepare(t, &fixtures[1], c, policy)
		}
		rolePreparing++
	}, func(c *resourcev4.Config) {
		c.ReferenceSlots = 2048
		c.ReservationSlots = 1024
		c.Limit[resourcev4.Items] = 16384
		if live != nil {
			c.Limit[resourcev4.DiskBytes] = 128 << 20
			c.Limit[resourcev4.ProviderBytes] = 128 << 20
			c.Limit[resourcev4.NativeHandles] = 16
		}
	})
	pair, configs := initialTestPairPrepared(t, protocolv4.DHProfileX25519, "stream", 4, func(h *cryptov4.HandshakeConfig, initial *InitialConfig) {
		if sharedClock != nil {
			h.Clock = sharedClock
			h.Deadline, err = timev4.NewAge(sharedClock, 60000, h.SessionDeadlineMS)
			if err != nil {
				t.Fatal(err)
			}
			initial.Deadline = h.Deadline
		}
		if live != nil && live.reopenPath != "" {
			// Distinct authenticated transport context for the new connection.
			previous := h.ContextDigest
			h.ContextDigest = sha256.Sum256(append(previous[:], byte(1)))
			if bytes.Count(h.FSA, previous[:]) != 1 {
				t.Fatal("transport context fixture changed")
			}
			h.FSA = bytes.Replace(h.FSA, previous[:], h.ContextDigest[:], 1)
		}
		h.Session = testSessionContract(t, h.Profile, "execution", 65536, 16, 0, h.Session.SessionNotAfterMS, 1<<20)
		h.Session.Resume = protocolv4.ResumePolicy{Enabled: true, MaxIssuedTokenDurationMS: 10000, MaxTokenBytes: 4980}
		mask, err := protocolv4.ApplicationResumeFeatureMask()
		if err != nil {
			t.Fatal(err)
		}
		h.Features |= mask
		prepare(h, initial)
		if live != nil && h.Role == 1 {
			executors[1] = live.install(t, &fixtures[1], body, policy)
			return
		}
		var history []string
		if live != nil && live.issueViaRPC {
			history = []string{policy.Namespace}
		}
		nativeTestRPCServicesHistory(t, &fixtures[h.Role], history, func(f *executorFixture, _ *SessionPlan, c *RPCServicesConfig) {
			executors[h.Role] = f
			c.Native = false
			c.ReferenceDomain = "test-domain"
			c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{body}, OfferWindowMS: 1000}}
			if live != nil && live.issueViaRPC {
				c.ResultRead = rpcv4.QueryBinding{Type: 3, Contract: [32]byte{9}}
				businessWire := bytes.Replace(body, []byte{1, 1, 2, 0}, []byte{1, 2, 2, 0}, 1)
				c.Routes.Methods = append(c.Routes.Methods, rpcv4.MethodRoutes{Contracts: [][]byte{businessWire}, OfferWindowMS: 1000})
				if live.content != nil {
					live.content.prepare(t)
					live.content.client(c)
				}
			}
		})
	})
	results := startInitialCorePair(pair, configs, &fixtures)
	var cores [2]*SessionCore
	for role := range 2 {
		out := waitInitialCoreOutcome(t, results[role])
		if out.err != nil {
			t.Fatal(out.err)
		}
		cores[role] = out.core
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ended := make(chan error, 2)
	publication := make(chan struct{})
	for _, core := range cores {
		if err := core.Runtime().bindApplicationPublication(publication); err != nil {
			t.Fatal(err)
		}
		go func() { ended <- core.Runtime().Run(ctx) }()
	}

	for role, core := range cores {
		r, f := core.plan.rpc, executors[role]
		plan := r.plan
		cfg := EnvironmentConfig{Services: true, ResultOwners: 16, Positions: 1, Clock: r.clock, RuntimeBytes: 65536}
		charge, err := EnvironmentCharge(cfg)
		if err != nil {
			t.Fatal(err)
		}
		env, err := NewEnvironment(cfg, f.reserve(t, 1, charge), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			env.Close()
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := env.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := env.Retire(); err != nil {
				t.Error(err)
			}
		})
		if live != nil && live.issueViaRPC {
			r.shortResultPosition, err = env.protectResult(env.reservation)
			if err != nil {
				t.Fatal(err)
			}
		}
		host := newEnvironmentSession(env, 0, context.Background())
		plan.mu.Lock()
		plan.host = host
		plan.mu.Unlock()
		host.mu.Lock()
		host.core, host.delivered = core, true
		host.mu.Unlock()
		var trust *sessionAdmissionTrustFixture
		trustBacking := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
		if sharedClock != nil {
			trust = newSessionAdmissionTrustProfile(t, f.root, trustBacking, r.owner, "live_authority", "transport", sharedClock)
		} else {
			trust = newSessionAdmissionTrustFixture(t, f.root, trustBacking, r.owner)
		}
		authority, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { authority.Close(nil) })
		if live != nil && live.issueViaRPC {
			r.deliveryFloor, err = authority.ReserveDeliveryFloor(r.refs[rpcServicesDeliveryFloor])
			if err != nil {
				t.Fatal("original delivery floor", err)
			}
		}
		plan.config.AuthorizeApplication = func(_ context.Context, request AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
			lease, err := request.ReserveLease(request.Binding(), nil, func(context.Context) error { return nil })
			if err == nil {
				err = lease.BindExecutionIdentity(request.Binding(), ExecutionSessionIdentity{Tenant: "tenant", Audience: "audience", Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}})
			}
			if err == nil && live != nil && role == 1 {
				err = lease.SetServiceAccess(policy.Namespace, policy.Type, true)
			}
			if err == nil && live != nil && live.issueViaRPC && role == 1 {
				err = lease.SetServiceAccess(live.businessPolicy.Namespace, live.businessPolicy.Type, true)
			}
			if err == nil && live != nil && live.content != nil && role == 1 {
				err = lease.SetServiceAccess(policy.Namespace, 4, true)
				if err == nil {
					err = lease.SetServiceAccess(policy.Namespace, 5, true)
				}
			}
			if err == nil && live != nil && live.issueViaRPC {
				err = lease.SetExecutionHistoryAccess(live.businessPolicy.Namespace, true, true)
			}
			return AuthorizeApplicationResult{Handlers: plan.config.Handlers, Lease: lease}, err
		}
		plan.claimed = true
		if err := plan.authorize(ctx, ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt, ApplicationProfile: "execution"}, authority.Check); err != nil {
			t.Fatal("authorize resume fixture", role, err)
		}
		if err := plan.lease.bindAuthorization(authority); err != nil {
			t.Fatal(err)
		}
		if live != nil && live.issueViaRPC {
			// This fixture owns Session transport cleanup; the original Environment
			// supervisor drives its ordinary service/result work through this host.
			host.mu.Lock()
			host.application = plan
			host.mu.Unlock()
			env.mu.Lock()
			env.positions[0] = host
			env.mu.Unlock()
			env.signalMaterials()
			t.Cleanup(func() { env.mu.Lock(); env.positions[0] = nil; env.mu.Unlock(); env.signalMaterials() })
		}
		if live != nil && role == 1 {
			r.dispatch.activate()
			if live.issueViaRPC {
				plan.mu.Lock()
				plan.resumePolicy = core.plan.config.Session.Resume
				enabled, err := protocolv4.ResumeFeatureSelected(core.Engine().NegotiatedFeatures())
				plan.resumePolicy.Enabled = plan.resumePolicy.Enabled && enabled
				plan.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		// Keep ordinary channel publication gated; this test owns the separate
		// target Stream and does not require management-channel initialization.
		for {
			r.mu.Lock()
			started := r.runtimeStarted
			r.mu.Unlock()
			if started {
				break
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			runtime.Gosched()
		}
		now, err := r.clock.Sample()
		if err != nil {
			t.Fatal(err)
		}
		notBefore, notAfter := now.LowerMS, now.LowerMS+1000
		if live != nil {
			var canonical [8192]byte
			registration, err := live.storage.store.ReadRegistration(ctx, policy.Digest, canonical[:], func() error { return nil })
			if err != nil || registration.OfferCount != 1 {
				t.Fatal("original recovery offer", err)
			}
			notBefore, notAfter = registration.Offers[0].NotBeforeMS, registration.Offers[0].NotAfterMS
		}
		var offer [256]byte
		wire, err := protocolv4.EncodeMap(offer[:], "AdmissionOffer", []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: policy.Digest[:]}, {Name: "not_before_ms", Number: notBefore}, {Name: "not_after_ms", Number: notAfter}})
		if err == nil {
			err = r.routes.RegisterOffer(policy.Digest, wire)
			if err == nil && live != nil && live.issueViaRPC {
				fields := []protocolv4.Field{{Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: live.businessPolicy.Digest[:]}, {Name: "not_before_ms", Number: notBefore}, {Name: "not_after_ms", Number: notAfter}}
				wire, err = protocolv4.EncodeMap(offer[:], "AdmissionOffer", fields)
				if err == nil {
					err = r.routes.RegisterOffer(live.businessPolicy.Digest, wire)
				}
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var stopped sync.Once
	stopPair := func() {
		stopped.Do(func() {
			for _, core := range cores {
				core.Close()
			}
			for range 2 {
				_ = waitRuntime(t, ended)
			}
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			for role, core := range cores {
				core.plan.rpc.Close()
				// Runtime owns its channel cleanup; Abort joins that same completion.
				if err := fixtures[role].plan.Abort(cleanup); err != nil {
					t.Error(err)
				}
				if err := pair[role].WaitCleanup(cleanup); err != nil {
					t.Error(err)
				}
			}
			cancel()
		})
	}
	t.Cleanup(stopPair)
	if live != nil {
		live.stopPair = stopPair
	}
	if live != nil {
		close(publication)
		if live.issueViaRPC {
			for _, core := range cores {
				r := core.plan.rpc
				for {
					r.mu.Lock()
					ready := r.channel != nil && r.dynamicChannels[0] != nil
					r.mu.Unlock()
					if ready {
						break
					}
					if ctx.Err() != nil {
						t.Fatal("original unary channel not ready", ctx.Err())
					}
					runtime.Gosched()
				}
			}
			if live.reopenPath == "" && live.content == nil {
				if live.referencePath != "" {
					live.referenceBacking = executors[0].reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.Items: 1})
				}
				live.issueCheckpointRPC(t, cores[0], ctx)
			}
		}
	}
	var streams [2]*StreamOwnership
	if live == nil {
		streams = factoryOpenPair(t, cores, ctx)
	} else {
		if live.deferTarget {
			return cores, streams, ResumeMethodDefinition{Kind: "example/raw", Contract: policy.Digest, DefaultResponseLimitBytes: 1024}, live.token, ctx
		}
		streams[0], err = cores[0].OpenStream(ctx, "example/raw", nil, streamTestDeadline(t, cores[0].Engine()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = streams[0].Cancel(); _ = streams[0].Release() })
		return cores, streams, ResumeMethodDefinition{Kind: "example/raw", Contract: policy.Digest, DefaultResponseLimitBytes: 1024}, live.token, ctx
	}
	resumeCodec, err := protocolv4.NewResumeCodec()
	if err != nil {
		t.Fatal(err)
	}
	token, err := resumeCodec.DecodeToken(initialFixture(t, "resume_signed_token_fields"), 0)
	if err != nil {
		t.Fatal(err)
	}
	return cores, streams, ResumeMethodDefinition{Kind: "example/raw", Contract: policy.Digest, DefaultResponseLimitBytes: 1024}, token, ctx
}

func readResumeBytes(ctx context.Context, stream *StreamOwnership, dst []byte) error {
	for offset := 0; offset < len(dst); {
		r, err := stream.ReadInto(ctx, dst[offset:])
		if err != nil {
			return err
		}
		if r.Progress.Filled == 0 {
			return errors.New("incomplete recovery message")
		}
		offset += int(r.Progress.Filled)
	}
	return nil
}

func readResumeRequest(t *testing.T, ctx context.Context, stream *StreamOwnership) (protocolv4.ApplicationHeader, protocolv4.ResumeRequest) {
	t.Helper()
	var prefix [2]byte
	if err := readResumeBytes(ctx, stream, prefix[:]); err != nil {
		t.Fatal(err)
	}
	headerBytes := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if err := readResumeBytes(ctx, stream, headerBytes); err != nil {
		t.Fatal(err)
	}
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	header, err := codec.Decode(headerBytes)
	if err != nil {
		t.Fatal(err)
	}
	if header.Kind() != "resume_request" {
		t.Fatal("unexpected request kind", header.Kind())
	}
	payload := make([]byte, header.Fields().PayloadBytes)
	if err := readResumeBytes(ctx, stream, payload); err != nil {
		t.Fatal(err)
	}
	resumeCodec, _ := protocolv4.NewResumeCodec()
	request, err := resumeCodec.DecodeRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	return header, request
}

func sendResumeResponse(t *testing.T, ctx context.Context, stream *StreamOwnership, request protocolv4.ApplicationHeader, result protocolv4.ResumeResult) {
	t.Helper()
	codec, _ := protocolv4.NewResumeCodec()
	var payload [4248]byte
	n, err := codec.EncodeResult(payload[:], result)
	if err != nil {
		t.Fatal(err)
	}
	h := request.Fields()
	h.Kind, h.AdmissionMode = 0, 0
	h.DeadlineAtMS, h.ResponseLimitBytes = 0, 0
	h.PayloadBytes = uint32(n)
	headerCodec, _ := protocolv4.NewApplicationHeaderCodec()
	var header [514]byte
	hn, _, err := headerCodec.Encode(header[2:], "resume_response", h)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(header[:2], uint16(hn))
	if _, err := stream.WriteAll(ctx, header[:hn+2]); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.WriteAll(ctx, payload[:n]); err != nil {
		t.Fatal(err)
	}
}

func TestResumeOriginalOperationBindsTargetAndReturnsSingleResult(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		t.Run(map[bool]string{false: "typed", true: "encoded"}[encoded], func(t *testing.T) {
			cores, streams, method, token, ctx := resumeClientPair(t)
			options := rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000}
			if _, err := cores[1].PrepareResume(ctx, method, streams[0], token, options); err == nil {
				t.Fatal("foreign Session captured target")
			}
			op, err := cores[0].PrepareResume(ctx, method, streams[0], token, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(op.Close)
			ref, err := op.Reference()
			if err != nil || !ref.Valid() {
				t.Fatal(ref, err)
			}
			if _, err := cores[0].PrepareResume(ctx, method, streams[0], token, options); !errors.Is(err, ErrStreamOwned) {
				t.Fatal("target qualification reused", err)
			}
			if _, err := streams[0].WriteAll(ctx, []byte("forbidden")); !errors.Is(err, ErrStreamOwned) {
				t.Fatal("raw I/O entered borrowed target", err)
			}
			if err := op.Start(ctx).Error; err != nil {
				t.Fatal(err)
			}
			if err := op.Start(ctx).Error; err != nil {
				t.Fatal("repeat Start did not join", err)
			}
			header, request := readResumeRequest(t, ctx, streams[1])
			if request.TransportContext != cores[0].Engine().TransportContextDigest() || request.StreamID != streams[0].handle.scope || header.Fields().OperationID != ref.Target().Operation || header.Fields().RequestDigest != ref.Target().RequestDigest {
				t.Fatal("original request binding changed")
			}
			wait, cancel := context.WithCancel(ctx)
			cancel()
			if _, _, err := op.TakeResult(wait); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			claims := token.Claims()
			want := protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: claims.Checkpoint, Generation: claims.Generation + 1}
			sendResumeResponse(t, ctx, streams[1], header, want)
			if _, err := streams[1].WriteAll(ctx, []byte("after-resume")); err != nil {
				t.Fatal(err)
			}
			status, err := op.WaitResultStatus(ctx)
			if err != nil || !status.Complete || !status.Available || status.Decoded || status.Submission.Flushed {
				t.Fatal(status, err)
			}
			if encoded {
				payload, status, err := op.TakeEncodedResult(ctx)
				codec, _ := protocolv4.NewResumeCodec()
				got, decodeErr := codec.DecodeResult(payload)
				if err != nil || decodeErr != nil || got != want || !status.Delivered || status.Outcome.ApplicationInputDelivered {
					t.Fatal(got, status, err, decodeErr)
				}
			} else {
				value, status, err := op.TakeResult(ctx)
				if err != nil || value != want || !status.Delivered || !status.Decoded || !status.Outcome.ApplicationInputDelivered {
					t.Fatal(value, status, err)
				}
			}
			if _, _, err := op.TakeResult(ctx); !errors.Is(err, ErrUnaryResultDelivered) {
				t.Fatal("repeated result consumed", err)
			}
			if _, _, err := op.TakeEncodedResult(ctx); !errors.Is(err, ErrUnaryResultDelivered) {
				t.Fatal("encoded result consumed twice", err)
			}
			op.Close()
			var after [12]byte
			if err := readResumeBytes(ctx, streams[0], after[:]); err != nil || !bytes.Equal(after[:], []byte("after-resume")) {
				t.Fatal("recovery consumed application bytes or closed target", string(after[:]), err)
			}
			cores[0].plan.rpc.AdvanceCalls()
			if err := op.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if got, err := op.Reference(); err != nil || got != ref {
				t.Fatal("cleanup lost query reference", err)
			}
		})
	}
}

func TestResumeAbandonRetainsOriginalBoundary(t *testing.T) {
	cores, streams, method, token, ctx := resumeClientPair(t)
	op, err := cores[0].PrepareResume(ctx, method, streams[0], token, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if _, err := op.AbandonResult(); !errors.Is(err, ErrUnaryNotStarted) {
		t.Fatal(err)
	}
	if err := op.Start(ctx).Error; err != nil {
		t.Fatal(err)
	}
	header, _ := readResumeRequest(t, ctx, streams[1])
	if _, err := op.AbandonResult(); err != nil {
		t.Fatal(err)
	}
	if _, err := streams[0].WriteAll(ctx, nil); !errors.Is(err, ErrStreamOwned) {
		t.Fatal("abandon returned unfinished qualification", err)
	}
	sendResumeResponse(t, ctx, streams[1], header, protocolv4.ResumeResult{Status: 2})
	m := op.resumeMessages()
	if err := m.waitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := op.TakeResult(ctx); !errors.Is(err, ErrUnaryResultAbandoned) {
		t.Fatal(err)
	}
	if _, _, err := op.TakeEncodedResult(ctx); !errors.Is(err, ErrUnaryResultAbandoned) {
		t.Fatal("encoded read lost abandonment", err)
	}
	if _, err := streams[1].WriteAll(ctx, []byte("safe")); err != nil {
		t.Fatal(err)
	}
	var payload [4]byte
	if err := readResumeBytes(ctx, streams[0], payload[:]); err != nil || string(payload[:]) != "safe" {
		t.Fatal(string(payload[:]), err)
	}
	op.Close()
	cores[0].plan.rpc.AdvanceCalls()
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestResumePrestartCloseReturnsUnusedTarget(t *testing.T) {
	cores, streams, method, token, ctx := resumeClientPair(t)
	op, err := cores[0].PrepareResume(ctx, method, streams[0], token, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := op.Reference()
	if err != nil {
		t.Fatal(err)
	}
	op.Close()
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if started := op.Start(ctx); started.Error == nil || started.Call != nil {
		t.Fatal("closed preparation regained Start", started)
	}
	if got, err := op.Reference(); err != nil || got != reference {
		t.Fatal("closed preparation lost query locator", err)
	}
	// Closing an unstarted preparation did not use either application direction.
	// A later explicit preparation may claim that exact same original target.
	next, err := cores[0].PrepareResume(ctx, method, streams[0], token, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	if _, err := streams[0].WriteAll(ctx, []byte("unstarted")); err != nil {
		t.Fatal(err)
	}
	var data [9]byte
	if err := readResumeBytes(ctx, streams[1], data[:]); err != nil || string(data[:]) != "unstarted" {
		t.Fatal("unused target lost raw I/O", string(data[:]), err)
	}
}

func TestResumeMismatchedProgressNeverDeliversResult(t *testing.T) {
	cores, streams, method, token, ctx := resumeClientPair(t)
	op, err := cores[0].PrepareResume(ctx, method, streams[0], token, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if err := op.Start(ctx).Error; err != nil {
		t.Fatal(err)
	}
	header, _ := readResumeRequest(t, ctx, streams[1])
	claims := token.Claims()
	sendResumeResponse(t, ctx, streams[1], header, protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: claims.Checkpoint, Generation: claims.Generation + 2})
	status, err := op.WaitResultStatus(ctx)
	if err != nil || !status.Complete || status.Available || !errors.Is(status.Outcome.Error, rpcv4.ErrAssociation) {
		t.Fatal("invalid progress became a result", status, err)
	}
	if _, _, err := op.TakeResult(ctx); !errors.Is(err, rpcv4.ErrAssociation) {
		t.Fatal("typed read lost recovery failure", err)
	}
	if _, _, err := op.TakeEncodedResult(ctx); !errors.Is(err, rpcv4.ErrAssociation) {
		t.Fatal("encoded read lost recovery failure", err)
	}
	op.Close()
	if err := op.resumeMessages().waitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	cores[0].plan.rpc.AdvanceCalls()
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := streams[0].WriteAll(ctx, []byte("unsafe")); err == nil {
		t.Fatal("invalid recovery returned raw authority")
	}
}

func TestResumeConfirmedSaveCannotReviveClosedTarget(t *testing.T) {
	cores, streams, method, token, ctx := resumeClientPair(t)
	op, err := cores[0].PrepareResume(ctx, method, streams[0], token, rpcv4.UnaryPreparation{DefaultLifetimeMS: 5000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	r := cores[0].plan.rpc
	storeOwner := r.owner
	storeOwner.Instance, storeOwner.Backing = [16]byte{245}, [16]byte{245}
	backing, err := r.root.Reserve(storeOwner, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1}, r.accounts[:r.accountCount]...)
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Release()
	var saved protocolv4.OperationReference
	store := ReferenceStoreBinding{Domain: "test-domain", Backing: backing, Store: referenceStoreFunc(func(_ context.Context, ref protocolv4.OperationReference) (ReferenceSaveOutcome, error) {
		saved = ref
		// This is synchronous target closure during the one original store call.
		// A definitive save remains queryable but cannot restore this target.
		streams[0].Revoke()
		return ReferenceSaveConfirmed, nil
	})}
	result, err := SavePreparedReference(ctx, op, store)
	if err == nil || !result.Attempted || result.Outcome != ReferenceSaveConfirmed || !saved.Valid() || result.Reference != saved {
		t.Fatal("lost persistence or handed out stale target", result, err)
	}
	if !op.Snapshot().Closed || op.Start(ctx).Error == nil {
		t.Fatal("confirmed persistence restored Start authority")
	}
	if err := op.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}
