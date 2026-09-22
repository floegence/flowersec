package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func awaitHandlerAdmissionSignal(t *testing.T, ctx context.Context, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("installed handler dispatcher did not reach the original callback", ctx.Err())
	}
}

func startHandlerAdmissionOpen(t *testing.T, core *SessionCore, ctx context.Context, kind string) <-chan factoryStreamResult {
	t.Helper()
	deadline := streamTestDeadline(t, core.Engine())
	done := make(chan factoryStreamResult, 1)
	go func() {
		stream, err := core.OpenStream(ctx, kind, []byte("admission metadata"), deadline)
		done <- factoryStreamResult{stream, err}
	}()
	return done
}

func awaitHandlerAdmissionOpen(t *testing.T, ctx context.Context, done <-chan factoryStreamResult) factoryStreamResult {
	t.Helper()
	select {
	case result := <-done:
		if result.stream != nil {
			t.Cleanup(func() {
				_ = result.stream.Cancel()
				if err := result.stream.Release(); err != nil {
					t.Error("original caller Stream retained its owner", err)
				}
			})
		}
		return result
	case <-ctx.Done():
		t.Fatal("installed handler dispatcher did not complete original OPEN", ctx.Err())
		return factoryStreamResult{}
	}
}

func TestSessionStreamHandlersAdmissionRejectsUnknownAndDeniedKinds(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		for _, deny := range []bool{false, true} {
			for receiver := range 2 {
				name := fmt.Sprintf("%s/receiver_%d/unknown", framing, receiver)
				if deny {
					name = fmt.Sprintf("%s/receiver_%d/authorization_denied", framing, receiver)
				}
				t.Run(name, func(t *testing.T) {
					var authorized, handled [2]atomic.Uint32
					cores, _, _, ctx := handlerCorePair(t, framing, func(role int) RawStreamHandlerConfig {
						return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationShort,
							AuthorizeOpen: func(context.Context, any, []byte) error {
								authorized[role].Add(1)
								if !deny || role != receiver {
									t.Error("unknown kind or wrong receiver entered authorization")
								}
								return errors.New("application policy denied OPEN")
							},
							Handler: func(context.Context, any, []byte, *StreamOwnership) error {
								handled[role].Add(1)
								t.Error("rejected OPEN entered an application handler")
								return nil
							}}
					}, nil)
					kind := "example/unregistered"
					if deny {
						kind = "example/raw"
					}
					result := awaitHandlerAdmissionOpen(t, ctx, startHandlerAdmissionOpen(t, cores[1-receiver], ctx, kind))
					if result.stream != nil || !errors.Is(result.err, ErrOpenRejected) {
						t.Fatal("unknown or denied kind was accepted", result.err)
					}
					wantAuthorization := uint32(0)
					if deny {
						wantAuthorization = 1
					}
					if authorized[receiver].Load() != wantAuthorization || authorized[1-receiver].Load() != 0 || handled[0].Load() != 0 || handled[1].Load() != 0 {
						t.Fatal("rejected OPEN entered an unauthorized callback", authorized[0].Load(), authorized[1].Load(), handled[0].Load(), handled[1].Load())
					}
					for _, core := range cores {
						if core.plan.receivePool.Outstanding() != 0 {
							t.Fatal("rejected OPEN retained receive promise capacity")
						}
						if err := core.Engine().CheckApplicationAuthorization(); err != nil {
							t.Fatal("ordinary OPEN rejection ended the Session", err)
						}
					}
				})
			}
		}
	}
}

func TestSessionStreamHandlersAdmissionRequiresOrdinaryExecutorPermit(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		t.Run(framing, func(t *testing.T) {
			var authorized, handled atomic.Uint32
			cores, fixtures, executors, ctx := handlerCorePair(t, framing, func(int) RawStreamHandlerConfig {
				return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationShort,
					AuthorizeOpen: func(context.Context, any, []byte) error {
						authorized.Add(1)
						t.Error("authorization ran without an original executor permit")
						return nil
					},
					Handler: func(context.Context, any, []byte, *StreamOwnership) error {
						handled.Add(1)
						t.Error("handler ran without an original executor permit")
						return nil
					}}
			}, nil)
			executor, fixture := executors[1], &fixtures[1]
			for range executor.config.Running {
				task := fixture.reserve(t, executor.TaskCharge())
				backing := fixture.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 64, resourcev4.Items: 1})
				permit, err := executor.TryAcquire(ApplicationShort, task, backing)
				if err != nil {
					t.Fatal("could not reserve original ordinary executor capacity", err)
				}
				t.Cleanup(permit.Close)
			}
			before := executor.Snapshot()
			if before.Running != executor.config.Running {
				t.Fatal("test did not occupy the original executor")
			}
			result := awaitHandlerAdmissionOpen(t, ctx, startHandlerAdmissionOpen(t, cores[0], ctx, "example/raw"))
			if result.stream != nil || !errors.Is(result.err, ErrOpenRejected) {
				t.Fatal("OPEN accepted without an ordinary executor permit", result.err)
			}
			if authorized.Load() != 0 || handled.Load() != 0 || executor.Snapshot() != before {
				t.Fatal("executor pressure started callback or borrowed another service", authorized.Load(), handled.Load(), executor.Snapshot())
			}
			if err := cores[1].Engine().CheckApplicationAuthorization(); err != nil {
				t.Fatal("ordinary executor pressure ended the Session", err)
			}
		})
	}
}

func TestSessionStreamHandlersAdmissionKeepsKindSlotThroughBothCallbacks(t *testing.T) {
	for _, phase := range []string{"authorization", "handler"} {
		for receiver := range 2 {
			t.Run(fmt.Sprintf("%s/receiver_%d", phase, receiver), func(t *testing.T) {
				authorizationEntered, authorizationRelease := make(chan struct{}), make(chan struct{})
				handlerEntered, handlerRelease := make(chan struct{}), make(chan struct{})
				releaseAuthorization := sync.OnceFunc(func() { close(authorizationRelease) })
				releaseHandler := sync.OnceFunc(func() { close(handlerRelease) })
				defer releaseAuthorization()
				defer releaseHandler()
				if phase == "handler" {
					releaseAuthorization()
				}
				var authorized, handled atomic.Uint32
				cores, _, _, ctx := handlerCorePair(t, "messages", func(int) RawStreamHandlerConfig {
					return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationShort,
						AuthorizeOpen: func(context.Context, any, []byte) error {
							if authorized.Add(1) == 1 {
								close(authorizationEntered)
							} else {
								t.Error("per-kind capacity refusal entered a second authorization")
							}
							<-authorizationRelease
							return nil
						},
						Handler: func(context.Context, any, []byte, *StreamOwnership) error {
							if handled.Add(1) == 1 {
								close(handlerEntered)
							} else {
								t.Error("per-kind capacity refusal entered a second handler")
							}
							<-handlerRelease
							return nil
						}}
				}, func(_ int, c *SessionStreamHandlerConfig) { c.Concurrency = 2 })
				first := startHandlerAdmissionOpen(t, cores[1-receiver], ctx, "example/raw")
				awaitHandlerAdmissionSignal(t, ctx, authorizationEntered)
				if phase == "handler" {
					awaitHandlerAdmissionSignal(t, ctx, handlerEntered)
				}
				second := awaitHandlerAdmissionOpen(t, ctx, startHandlerAdmissionOpen(t, cores[1-receiver], ctx, "example/raw"))
				if second.stream != nil || !errors.Is(second.err, ErrOpenRejected) || authorized.Load() != 1 {
					t.Fatal("same kind exceeded its original callback concurrency", second.err, authorized.Load())
				}
				wantHandlers := uint32(0)
				if phase == "handler" {
					wantHandlers = 1
				}
				if handled.Load() != wantHandlers {
					t.Fatal("second OPEN entered a handler while the kind slot was occupied", handled.Load())
				}
				releaseAuthorization()
				awaitHandlerAdmissionSignal(t, ctx, handlerEntered)
				result := awaitHandlerAdmissionOpen(t, ctx, first)
				if result.err != nil || result.stream == nil || handled.Load() != 1 {
					t.Fatal("capacity rejection disrupted the original accepted OPEN", result.err, handled.Load())
				}
			})
		}
	}
}

func TestSessionStreamHandlersAdmissionPlanCloseBeforeAcceptPreventsHandler(t *testing.T) {
	for receiver := range 2 {
		t.Run(fmt.Sprintf("receiver_%d", receiver), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			var handled atomic.Uint32
			cores, _, _, ctx := handlerCorePair(t, "stream", func(int) RawStreamHandlerConfig {
				return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationShort,
					AuthorizeOpen: func(context.Context, any, []byte) error {
						close(entered)
						<-release
						return nil
					},
					Handler: func(context.Context, any, []byte, *StreamOwnership) error {
						handled.Add(1)
						t.Error("registration closed before acceptance entered a handler")
						return nil
					}}
			}, nil)
			opening := startHandlerAdmissionOpen(t, cores[1-receiver], ctx, "example/raw")
			awaitHandlerAdmissionSignal(t, ctx, entered)
			plan := cores[receiver].plan.config.Handlers.Plan
			plan.Close()
			select {
			case <-plan.Done():
				t.Fatal("closing registration forgot the original authorization callback")
			default:
			}
			finish()
			result := awaitHandlerAdmissionOpen(t, ctx, opening)
			if result.stream != nil || !errors.Is(result.err, ErrOpenRejected) || handled.Load() != 0 {
				t.Fatal("registration closed before acceptance entered a handler", result.err, handled.Load())
			}
			if err := plan.WaitCleanup(ctx); err != nil {
				t.Fatal("closed registration retained the completed original callback", err)
			}
		})
	}
}

// Keep the original maintenance publication in its actual provider call. The
// complete encrypted record still reaches the original peer after release.
type handlerAdmissionHeldWriter struct {
	writer           io.Writer
	profile          string
	kind             protocolv4.FrameType
	entered, release chan struct{}
	once             sync.Once
}

func (w *handlerAdmissionHeldWriter) Write(data []byte) (int, error) {
	kind, _, _, err := protocolv4.ParseRecord(data, w.profile, protocolv4.MaxPayloadLength)
	if err != nil {
		return 0, err
	}
	if kind == w.kind {
		w.once.Do(func() {
			close(w.entered)
			<-w.release
		})
	}
	return w.writer.Write(data)
}

func installHandlerAdmissionWriter(t *testing.T, core *SessionCore, ctx context.Context, kind protocolv4.FrameType) (*handlerAdmissionHeldWriter, func()) {
	t.Helper()
	_, profile := core.Engine().SessionBinding()
	w := &handlerAdmissionHeldWriter{profile: profile, kind: kind, entered: make(chan struct{}), release: make(chan struct{})}
	resume := sync.OnceFunc(func() { close(w.release) })
	t.Cleanup(resume)
	for {
		writer := core.plan.writer
		writer.mu.Lock()
		if !writer.active {
			w.writer, writer.writer = writer.writer, w
			writer.mu.Unlock()
			return w, resume
		}
		writer.mu.Unlock()
		if err := ctx.Err(); err != nil {
			t.Fatal("maintenance writer did not finish before test installation", err)
		}
		runtime.Gosched()
	}
}

func waitHandlerAdmissionPredicate(t *testing.T, ctx context.Context, description string, ready func() bool) {
	t.Helper()
	for !ready() {
		if err := ctx.Err(); err != nil {
			t.Fatal(description, err)
		}
		runtime.Gosched()
	}
}

func TestSessionStreamHandlersAdmissionRetriesOriginalBusyMaintenanceWriter(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		for _, decision := range []string{"unknown_kind", "dispatcher_concurrency", "accepted"} {
			t.Run(framing+"/"+decision, func(t *testing.T) {
				handlerEntered, handlerRelease := make(chan struct{}), make(chan struct{})
				finishHandler := sync.OnceFunc(func() { close(handlerRelease) })
				defer finishHandler()
				var handled atomic.Uint32
				cores, _, _, ctx := handlerCorePair(t, framing, func(int) RawStreamHandlerConfig {
					return RawStreamHandlerConfig{Kind: "example/raw", Slots: 2, WorkClass: ApplicationShort,
						Handler: func(context.Context, any, []byte, *StreamOwnership) error {
							if decision == "unknown_kind" || handled.Add(1) != 1 {
								t.Error("rejected or repeated OPEN entered a handler")
								return nil
							}
							close(handlerEntered)
							<-handlerRelease
							return nil
						}}
				}, func(_ int, c *SessionStreamHandlerConfig) {
					c.Concurrency, c.TimeoutMS = 1, 5000
				})
				scope := uint64(1)
				if decision == "dispatcher_concurrency" {
					first := startHandlerAdmissionOpen(t, cores[0], ctx, "example/raw")
					awaitHandlerAdmissionSignal(t, ctx, handlerEntered)
					if result := awaitHandlerAdmissionOpen(t, ctx, first); result.err != nil || result.stream == nil {
						t.Fatal("first original handler was not accepted", result.err)
					}
					scope = 3
				}
				blocked, resumeWriter := installHandlerAdmissionWriter(t, cores[1], ctx, protocolv4.FramePing)
				defer resumeWriter()
				probe, err := cores[1].Admission().liveness.Begin(5000)
				if err != nil {
					t.Fatal(err)
				}
				defer probe.Release()
				published := make(chan error, 1)
				go func() {
					result, err := probe.Publish(ctx)
					if err == nil && !result.Complete {
						err = errors.New("original PING publication did not complete")
					}
					published <- err
				}()
				awaitHandlerAdmissionSignal(t, ctx, blocked.entered)
				kind := "example/raw"
				if decision == "unknown_kind" {
					kind = "example/unregistered"
				}
				opening := startHandlerAdmissionOpen(t, cores[0], ctx, kind)
				a := cores[1].Admission()
				h := OpenHandle{a, scope}
				waitHandlerAdmissionPredicate(t, ctx, "original OPEN did not wait for its busy maintenance publisher", func() bool {
					a.mu.Lock()
					defer a.mu.Unlock()
					s, err := a.slot(h)
					return a.closed || err == nil && s.phase == openPending && s.outcomeWaiting && !s.deciding
				})
				a.mu.Lock()
				s, lookupErr := a.slot(h)
				retained := !a.closed && lookupErr == nil && !s.accepted && s.phase == openPending
				a.mu.Unlock()
				if !retained {
					t.Fatal("local maintenance pressure closed Session or selected a second outcome")
				}
				select {
				case result := <-opening:
					t.Fatal("OPEN completed while its sole maintenance publisher was blocked", result.err)
				default:
				}
				resumeWriter()
				if err := waitRuntime(t, published); err != nil {
					t.Fatal(err)
				}
				result := awaitHandlerAdmissionOpen(t, ctx, opening)
				if decision == "accepted" {
					if result.err != nil || result.stream == nil {
						t.Fatal("busy writer consumed the original acceptance allocation", result.err)
					}
					awaitHandlerAdmissionSignal(t, ctx, handlerEntered)
				} else if result.stream != nil || !errors.Is(result.err, ErrOpenRejected) {
					t.Fatal("writer release did not publish the original sole rejection", result.err)
				}
				for _, core := range cores {
					if err := core.Engine().CheckApplicationAuthorization(); err != nil {
						t.Fatal("ordinary publication contention ended the Session", err)
					}
				}
				cores[0].Admission().mu.Lock()
				next := cores[0].Admission().nextOrdinal
				cores[0].Admission().mu.Unlock()
				if next != (scope+1)/2+1 {
					t.Fatal("publication retry allocated another OPEN identity", next)
				}
			})
		}
	}
}

func TestSessionStreamHandlersAdmissionTimeoutDuringAcceptedPublicationCancelsOriginalOpen(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		t.Run(framing, func(t *testing.T) {
			authorized := make(chan context.Context, 1)
			var handled atomic.Uint32
			cores, _, _, ctx := handlerCorePair(t, framing, func(int) RawStreamHandlerConfig {
				return RawStreamHandlerConfig{Kind: "example/raw", Slots: 1, WorkClass: ApplicationShort,
					AuthorizeOpen: func(ctx context.Context, _ any, _ []byte) error { authorized <- ctx; return nil },
					Handler: func(context.Context, any, []byte, *StreamOwnership) error {
						handled.Add(1)
						t.Error("timed-out acceptance entered a handler")
						return nil
					}}
			}, func(_ int, c *SessionStreamHandlerConfig) { c.TimeoutMS = 300 })
			blocked, resumeWriter := installHandlerAdmissionWriter(t, cores[1], ctx, protocolv4.FrameStreamAck)
			defer resumeWriter()
			opening := startHandlerAdmissionOpen(t, cores[0], ctx, "example/raw")
			awaitHandlerAdmissionSignal(t, ctx, blocked.entered)
			var invocation context.Context
			select {
			case invocation = <-authorized:
			case <-ctx.Done():
				t.Fatal("original authorization did not supply invocation context", ctx.Err())
			}
			a := cores[1].Admission()
			h := OpenHandle{a, 1}
			a.mu.Lock()
			s, err := a.slot(h)
			accepted := err == nil && s.accepted && s.phase == openLive && s.owner == nil && s.preparationActive
			a.mu.Unlock()
			if !accepted {
				t.Fatal("test did not suspend the original accepted publication before ownership handoff")
			}
			awaitHandlerAdmissionSignal(t, ctx, invocation.Done())
			if handled.Load() != 0 {
				t.Fatal("handler ran before publication completed")
			}
			resumeWriter()
			result := awaitHandlerAdmissionOpen(t, ctx, opening)
			if result.err != nil || result.stream == nil {
				t.Fatal("completed accepted publication lost its peer-visible outcome", result.err)
			}
			waitHandlerAdmissionPredicate(t, ctx, "timed-out accepted job retained its preparation tail", func() bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				s, err := a.slot(h)
				return a.closed || err != nil || !s.preparationActive
			})
			a.mu.Lock()
			s, err = a.slot(h)
			cancelled := !a.closed && (err == nil && s.accepted && s.cancelled && s.owner == nil || err != nil && a.isStable(h.scope))
			a.mu.Unlock()
			if !cancelled || handled.Load() != 0 {
				t.Fatal("timeout left an unowned accepted live flow or entered handler")
			}
		})
	}
}
