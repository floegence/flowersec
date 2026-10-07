package sessionv4

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestSessionStreamHandlersAcceptedUnboundCleanupRetainsOriginalInvocation(t *testing.T) {
	for _, framing := range []string{"stream", "messages"} {
		for _, failure := range []string{"canceled-outcome-observation", "expired-service-binding"} {
			t.Run(framing+"/"+failure, func(t *testing.T) {
				setupContexts := make(chan context.Context, 2)
				var served atomic.Uint32
				options := delegatedRawOptions()
				if failure == "expired-service-binding" {
					options.Connection.TimeoutMS = 300
				}
				cores, _, _, ctx := handlerCorePair(t, framing, func(int) RawStreamHandlerConfig {
					return RawStreamHandlerConfig{Kind: "example/native", Slots: 1, WorkClass: ApplicationShort,
						Delegated: &DelegatedStreamService{Options: options,
							Setup: func(ctx context.Context, _ any, _ []byte) (DelegatedStreamServe, error) {
								setupContexts <- ctx
								return func(_ context.Context, conn net.Conn) error {
									served.Add(1)
									var payload [4]byte
									if _, err := io.ReadFull(conn, payload[:]); err != nil {
										return err
									}
									_, err := conn.Write(payload[:])
									return err
								}, nil
							}}}
				}, func(_ int, config *SessionStreamHandlerConfig) {
					config.Concurrency, config.ServiceTarget = 1, 1
					if failure == "canceled-outcome-observation" {
						config.TimeoutMS = 300
					}
				})
				publication, releasePublication := installHandlerAdmissionWriter(t, cores[1], ctx, protocolv4.FrameStreamAck)
				defer releasePublication()
				terminal, releaseTerminal := installHandlerAdmissionWriter(t, cores[0], ctx, protocolv4.FrameStreamAck)
				defer releaseTerminal()
				opening := startHandlerAdmissionOpen(t, cores[0], ctx, "example/native")
				awaitHandlerAdmissionSignal(t, ctx, publication.entered)
				var invocation context.Context
				select {
				case invocation = <-setupContexts:
				case <-ctx.Done():
					t.Fatal("original delegated setup did not run", ctx.Err())
				}
				a, plan := cores[1].Admission(), cores[1].plan
				handle := OpenHandle{a, 1}
				a.mu.Lock()
				slot, err := a.slot(handle)
				accepted := err == nil && slot.accepted && slot.owner == nil && slot.preparationActive
				var flow *StreamFlow
				if accepted {
					flow = slot.flow
				}
				a.mu.Unlock()
				if !accepted || flow == nil {
					t.Fatal("original publication did not retain the unbound accepted flow", err)
				}
				flow.send.mu.Lock()
				queue := flow.send.queueOwner
				flow.send.mu.Unlock()
				if failure == "canceled-outcome-observation" {
					awaitHandlerAdmissionSignal(t, ctx, invocation.Done())
				} else {
					// The service's original age started before Setup. Keep its
					// accepted publication pending for that age, while the ordinary
					// invocation stays live so failure occurs in ownership binding.
					timer := time.NewTimer(time.Duration(options.Connection.TimeoutMS) * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					if err := invocation.Err(); err != nil {
						t.Fatal("service binding case canceled outcome observation", err)
					}
				}
				releasePublication()
				first := awaitHandlerAdmissionOpen(t, ctx, opening)
				if first.err != nil || first.stream == nil {
					t.Fatal("original accepted publication lost its peer-visible result", first.err)
				}
				awaitHandlerAdmissionSignal(t, ctx, terminal.entered)
				waitHandlerAdmissionPredicate(t, ctx, "unbound invocation never joined its original terminal wait", func() bool {
					a.mu.Lock()
					defer a.mu.Unlock()
					slot, err := a.slot(handle)
					if err != nil || !slot.preparationActive {
						t.Fatal("unbound invocation released preparation before flow cleanup", err)
					}
					return slot.outcomeWaiting && slot.cancelled && !slot.coreCleaned && slot.owner == nil
				})
				plan.mu.Lock()
				floorHeld := len(plan.serviceFloors) == 1 && plan.serviceFloors[0].used
				plan.mu.Unlock()
				d := plan.dispatcher
				d.mu.Lock()
				invocationHeld := d.active == 1 && d.services == 1
				d.mu.Unlock()
				if !floorHeld || !invocationHeld || served.Load() != 0 {
					t.Fatal("failed binding released the original service or entered Serve", floorHeld, invocationHeld, served.Load())
				}
				releaseTerminal()
				waitHandlerAdmissionPredicate(t, ctx, "unbound invocation did not complete real flow cleanup", func() bool {
					d.mu.Lock()
					released := d.active == 0 && d.services == 0
					d.mu.Unlock()
					return released
				})
				a.mu.Lock()
				slot, err = a.slot(handle)
				coreCleaned := !a.closed && (err == nil && slot.coreCleaned && !slot.preparationActive || err != nil && a.isStable(handle.scope))
				a.mu.Unlock()
				flow.receive.pool.mu.Lock()
				receiveCleaned := flow.receive.cleaned
				flow.receive.pool.mu.Unlock()
				queue.mu.Lock()
				queueCleaned := queue.cleaned
				queue.mu.Unlock()
				plan.mu.Lock()
				floorReleased := !plan.serviceFloors[0].used
				plan.mu.Unlock()
				if !coreCleaned || !receiveCleaned || !queueCleaned || !floorReleased {
					t.Fatal("unbound cleanup did not return original backing", coreCleaned, receiveCleaned, queueCleaned, floorReleased)
				}
				second := awaitHandlerAdmissionOpen(t, ctx, startHandlerAdmissionOpen(t, cores[0], ctx, "example/native"))
				if second.err != nil || second.stream == nil {
					t.Fatal("healthy Session could not reuse its original service position", second.err)
				}
				if n, err := second.stream.WriteAll(ctx, []byte("next")); err != nil || n != 4 {
					t.Fatal("reused delegated stream write", n, err)
				}
				if err := second.stream.CloseWrite(ctx); err != nil {
					t.Fatal(err)
				}
				var reply [4]byte
				for offset := 0; offset < len(reply); {
					read, err := second.stream.ReadInto(ctx, reply[offset:])
					if err != nil || read.Progress.Filled == 0 {
						t.Fatal("reused delegated stream read", read, err)
					}
					offset += int(read.Progress.Filled)
				}
				if string(reply[:]) != "next" || served.Load() != 1 {
					t.Fatal("reused delegated service did not preserve its original protocol", reply, served.Load())
				}
				if err := second.stream.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				waitDispatcherServices(t, ctx, d, 0)
				for _, core := range cores {
					if err := core.Engine().CheckApplicationAuthorization(); err != nil {
						t.Fatal("failed original binding terminated the healthy Session", err)
					}
				}
			})
		}
	}
}
