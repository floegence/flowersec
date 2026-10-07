package transporttest

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func closeControllerTest(t *testing.T, controller *flowersec.ConnectionController) {
	t.Helper()
	controller.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := controller.WaitCleanup(ctx); err != nil {
		t.Errorf("original controller cleanup: %v", err)
	}
}

func TestProductionControllerArtifactCurrentPinConnects(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			endpoint, err := OpenProductDirectEndpoint(ctx, kind)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := endpoint.Close(); err != nil {
					t.Errorf("original endpoint cleanup: %v", err)
				}
			}()
			source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Errorf("original source cleanup: %v", err)
				}
			}()
			controller, err := source.NewController(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer closeControllerTest(t, controller)
			if err := controller.Start(ctx); err != nil {
				t.Fatal(err)
			}
			client, err := controller.WaitForSession(ctx)
			if err != nil {
				t.Fatalf("current pin connect failed: %v", err)
			}
			server, err := source.WaitServer(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := source.NewPair(ctx, client, server)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Errorf("original pair cleanup: %v", err)
				}
			}()
			payload := []byte("current-pin-controller")
			response, err := pair.CallEcho(ctx, payload)
			if err != nil || !bytes.Equal(response, payload) {
				t.Fatalf("original service echo = %q, %v", response, err)
			}
			if source.AcquisitionCount() != 1 || source.SpendCount(0) != 1 || source.RetireCount(0) != 0 {
				t.Fatalf("original acquisition/spend/retirement = %d/%d/%d", source.AcquisitionCount(), source.SpendCount(0), source.RetireCount(0))
			}
		})
	}
}

func TestProductionControllerEstablishedSessionSurvivesPinPolicyExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	endpoint, err := OpenProductDirectEndpoint(ctx, carrier.KindWebSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := endpoint.Close(); err != nil {
			t.Errorf("original endpoint cleanup: %v", err)
		}
	}()
	source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanExpiringPin})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Errorf("original source cleanup: %v", err)
		}
	}()
	controller, err := source.NewController(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeControllerTest(t, controller)
	if err := controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	client, err := controller.WaitForSession(ctx)
	if err != nil {
		t.Fatalf("controller did not establish before pin expiry: %v, snapshot=%+v", err, controller.Snapshot())
	}
	server, err := source.WaitServer(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := source.NewPair(ctx, client, server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Errorf("original pair cleanup: %v", err)
		}
	}()
	expires := source.records[0].pinExpiresMS
	if expires == 0 {
		t.Fatal("independent signed pin has no expiry")
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		sample, err := source.reporter.AuthorityClock().Sample()
		if err != nil {
			t.Fatal(err)
		}
		if sample.Interval.LowerMS > expires {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(context.Cause(ctx))
		}
	}
	probe, err := client.ProbeLiveness(ctx, 1000)
	if err != nil || !probe.Complete {
		t.Fatalf("established session after pin expiry: probe=%+v, error=%v", probe, err)
	}
	current, err := controller.CaptureSession()
	if err != nil || current != client || !controller.Snapshot().Current {
		t.Fatalf("original established session was replaced after pin expiry: %v, snapshot=%+v", err, controller.Snapshot())
	}
	if source.AcquisitionCount() != 1 || source.SpendCount(0) != 1 {
		t.Fatalf("pin expiry caused another acquisition: count=%d, spend=%d", source.AcquisitionCount(), source.SpendCount(0))
	}
	payload := []byte("established-after-pin-expiry")
	response, err := pair.CallEcho(ctx, payload)
	if err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("established service after pin expiry = %q, %v", response, err)
	}
}

// A rejected DER pin cannot spend a lease, publish a replacement, or remove
// the current Session. A subsequent explicit replacement uses a fresh signed
// record, while retain keeps old stream and RPC handles on their original path.
func TestCurrentControllerPinFailureThenReplacementPreservesOriginalHandles(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(string(kind)+"/"+profile, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
				defer cancel()
				endpoint, err := OpenProductDirectEndpointWithProfile(ctx, kind, profile)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := endpoint.Close(); err != nil {
						t.Errorf("original listener cleanup: %v", err)
					}
				}()
				source, err := NewProductControllerArtifactSource(endpoint, []ControllerArtifactPlan{ControllerPlanCurrentPin, ControllerPlanStalePin, ControllerPlanCurrentPin})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := source.Close(); err != nil {
						t.Errorf("original source cleanup: %v", err)
					}
				}()
				controller, err := source.NewController(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer closeControllerTest(t, controller)
				if err = controller.Start(ctx); err != nil {
					t.Fatal(err)
				}
				first, err := controller.WaitForSession(ctx)
				if err != nil {
					t.Fatal(err)
				}
				firstServer, err := source.WaitServer(ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				firstPair, err := source.NewPair(ctx, first, firstServer)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := firstPair.Close(); err != nil {
						t.Errorf("old original pair cleanup: %v", err)
					}
				}()
				opened, err := first.OpenStream(ctx, "native-isolation", flowersec.EmptyStreamMetadata())
				if err != nil {
					t.Fatal(err)
				}
				incoming, err := firstServer.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer opened.Reset()
				defer incoming.Stream.Reset()
				if _, err = opened.WriteAll(ctx, []byte("before")); err != nil {
					t.Fatal(err)
				}
				prefix := make([]byte, 6)
				if _, err = io.ReadFull(incoming.Stream, prefix); err != nil || string(prefix) != "before" {
					t.Fatalf("old original stream prefix: %q %v", prefix, err)
				}
				now, err := source.reporter.AuthorityClock().Sample()
				if err != nil {
					t.Fatal(err)
				}
				options := flowersec.ControllerReplaceOptions{Retirement: flowersec.ControllerRetain, RetainUntilMS: now.Interval.UpperMS + 10000}
				refused, err := controller.ReplaceSession(ctx, options)
				if err == nil || refused.CurrentSwitched || refused.Current != nil || refused.PreviousRetained {
					t.Fatalf("stale DER pin published replacement facts: %+v %v", refused, err)
				}
				current, err := controller.CaptureSession()
				if err != nil || current != first {
					t.Fatalf("failed original pin displaced the current Session: %v", err)
				}
				settled, stop := context.WithTimeout(ctx, 5*time.Second)
				ticker := time.NewTicker(20 * time.Millisecond)
				for source.RetireCount(1) != 1 || controller.Snapshot().Pending {
					select {
					case <-ticker.C:
					case <-settled.Done():
						ticker.Stop()
						stop()
						t.Fatalf("refused original pin retained its preparation/material tail: retired=%d snapshot=%+v cleanup=%+v report=%+v", source.RetireCount(1), controller.Snapshot(), controller.CleanupStatus(), controller.LocalReport())
					}
				}
				ticker.Stop()
				stop()
				if source.AcquisitionCount() != 2 || source.SpendCount(0) != 1 || source.SpendCount(1) != 0 || controller.Snapshot().WaitingRetry {
					t.Fatalf("pin refusal retried or spent material: acquisitions=%d first=%d refused=%d snapshot=%+v", source.AcquisitionCount(), source.SpendCount(0), source.SpendCount(1), controller.Snapshot())
				}
				if source.records[1].accepted.Claimed() {
					t.Fatal("wrong DER pin reached credential-bearing accepted lookup")
				}
				payload := []byte("current-after-pin-refusal")
				response, err := firstPair.CallEcho(ctx, payload)
				if err != nil || !bytes.Equal(response, payload) {
					t.Fatalf("old original service after refused pin: %q %v", response, err)
				}
				now, err = source.reporter.AuthorityClock().Sample()
				if err != nil {
					t.Fatal(err)
				}
				options.RetainUntilMS = now.Interval.UpperMS + 10000
				replaced, err := controller.ReplaceSession(ctx, options)
				if err != nil || !replaced.CurrentSwitched || !replaced.PreviousRetained || replaced.Previous != first || replaced.Current == nil || replaced.Current == first || replaced.RetirementError != nil {
					t.Fatalf("fresh pin replacement/retain: %+v %v", replaced, err)
				}
				secondServer, err := source.WaitServer(ctx, 2)
				if err != nil {
					t.Fatal(err)
				}
				secondPair, err := source.NewPair(ctx, replaced.Current, secondServer)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := secondPair.Close(); err != nil {
						t.Errorf("new original pair cleanup: %v", err)
					}
				}()
				current, err = controller.CaptureSession()
				if err != nil || current != replaced.Current {
					t.Fatalf("controller did not publish the fresh original Session: %v", err)
				}
				for index, pair := range []*ProductDirectPair{firstPair, secondPair} {
					payload := []byte{byte(index), 0x63}
					response, err := pair.CallEcho(ctx, payload)
					if err != nil || !bytes.Equal(response, payload) {
						t.Fatalf("original retained/current service %d: %x %v", index, response, err)
					}
				}
				if _, err = opened.WriteAll(ctx, []byte("after")); err != nil {
					t.Fatal(err)
				}
				if err = opened.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				suffix, err := io.ReadAll(incoming.Stream)
				if err != nil || string(suffix) != "after" {
					t.Fatalf("old stream crossed into replacement: %q %v", suffix, err)
				}
				if _, err = incoming.Stream.WriteAll(ctx, []byte("old-path-response")); err != nil {
					t.Fatal(err)
				}
				if err = incoming.Stream.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				response, err = io.ReadAll(opened)
				if err != nil || string(response) != "old-path-response" {
					t.Fatalf("retained old response: %q %v", response, err)
				}
				if err = opened.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				if err = incoming.Stream.Finish(ctx); err != nil {
					t.Fatal(err)
				}
				if source.AcquisitionCount() != 3 || source.SpendCount(0) != 1 || source.SpendCount(1) != 0 || source.SpendCount(2) != 1 || source.RetireCount(1) != 1 {
					t.Fatal("pin replacement changed the original acquisition/spend/retirement facts")
				}
			})
		}
	}
}
