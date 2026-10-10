package transporttest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestDirectCapacityGroupsKeepOriginalRoutesAndSharedTLSPin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	owner, err := openProductDirectCapacityEndpoint(ctx, carrier.KindWebTransport, "127.0.0.1", releaseRunnerOrigin, 64, 128, 64, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(owner.groups) != 2 || owner.groups[0].positions != 63 || owner.groups[1].positions != 1 {
		t.Fatal("aggregate did not retain the original independent deployment groups")
	}
	pin, err := owner.CertificateHashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range owner.groups {
		actual, err := group.endpoint.CertificateHashBase64URL()
		if err != nil || actual != pin {
			t.Fatal("original group TLS leaf differs from the runner pin", err)
		}
		capacity := group.endpoint.reporter.Capacity
		if capacity == nil || capacity.Sessions != uint32(group.positions+1) || capacity.Materials != uint32(group.positions+1) || capacity.BusinessStreams != 128 {
			t.Fatal("group installation omitted a base plan or the original stream workload")
		}
		if group.endpoint.reporter.ActivationWindowMS != productCapacityActivationWindowMS {
			t.Fatal("capacity deployment omitted its finite signed preparation window")
		}
	}
	for i := range 64 {
		artifact, err := owner.IssueBrowserArtifact()
		if err != nil {
			t.Fatalf("issue original browser position %d: %v", i, err)
		}
		group := &owner.groups[i/productDirectCapacityGroupPositions]
		if artifact.endpoint != group.endpoint {
			t.Fatal("browser artifact escaped its original deployment")
		}
		route, err := currentCandidateURL(artifact.original.Route)
		if err != nil || route != group.endpoint.CandidateURL() {
			t.Fatal("original signed route was moved to another listener", err)
		}
		if err := artifact.CloseOriginalBrowser(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.IssueBrowserArtifact(); err == nil {
		t.Fatal("exhausted original aggregate reissued browser material")
	}
}

func TestDirectCapacityPositionsShareDeploymentAndRetireIndependently(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindRawQUIC, carrier.KindWebTransport} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			owner, err := OpenProductDirectCapacityEndpoint(ctx, kind, 4)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := owner.PrepareCapacity(ctx, 4); err != nil {
				t.Fatal(err)
			}
			endpoint := owner.groups[0].endpoint
			base := endpoint.capacityClient.Runtime
			for index, prepared := range endpoint.prepared {
				runtime := prepared.client.Runtime
				if runtime.Authority.Root != base.Authority.Root || runtime.Environment != base.Environment || runtime.Executor != base.Executor {
					t.Fatal("position reinstalled its original deployment")
				}
				if runtime.Authority.Scope[0].Session == base.Authority.Scope[0].Session {
					t.Fatal("position borrowed the base Session account")
				}
				for _, sibling := range endpoint.prepared[:index] {
					if runtime.Authority.Scope[0].Session == sibling.client.Runtime.Authority.Scope[0].Session {
						t.Fatal("positions share a Session account")
					}
				}
			}
			pairs := make([]*ProductDirectPair, 4)
			errorsByPosition := make([]error, 4)
			var workers sync.WaitGroup
			for index := range pairs {
				workers.Add(1)
				go func() {
					defer workers.Done()
					pairs[index], errorsByPosition[index] = owner.Connect(ctx)
				}()
			}
			workers.Wait()
			for index, pair := range pairs {
				if pair != nil {
					defer func() {
						if err := pair.Close(); err != nil {
							t.Error(err)
						}
					}()
				}
				if errorsByPosition[index] != nil || pair == nil || pair.SpendCount() != 1 {
					t.Fatalf("position %d original spend/READY: %v", index, errorsByPosition[index])
				}
			}
			if err := pairs[0].Close(); err != nil {
				t.Fatal(err)
			}
			for _, pair := range pairs[1:] {
				payload := []byte("sibling-remains-live")
				got, err := pair.CallEcho(ctx, payload)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("position Close retired a sibling deployment", err)
				}
			}
			for _, pair := range pairs {
				if err := pair.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if snapshot := base.Authority.Root.Snapshot(); snapshot.Closed {
				t.Fatal("last position Close retired the endpoint-owned root")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if snapshot := base.Authority.Root.Snapshot(); !snapshot.Closed || !snapshot.CleanupComplete || snapshot.Reservations != 0 || snapshot.References != 0 || snapshot.ResultOwners != 0 {
				t.Fatalf("original deployment retained physical owners: %+v", snapshot)
			}
		})
	}
}

func TestDirectAggregatePreparationTransfersBeyondCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := OpenProductDirectCapacityEndpoint(ctx, carrier.KindWebSocket, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	preparation, stop := context.WithCancel(ctx)
	defer stop()
	if err := owner.PrepareCapacity(preparation, 2); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := owner.PrepareCapacity(ctx, 2); err == nil {
		t.Fatal("aggregate preparation was reusable")
	}
	// Preprovisioned material can wait longer than an operation. Expire the
	// construction templates without waiting for the default ten-second age.
	var constructionDeadlines []*timev4.Deadline
	for _, prepared := range owner.groups[0].endpoint.prepared {
		h := prepared.client.Runtime.Authority
		deadline, err := timev4.NewAge(h.Clock, 20, h.Admission[0].Core.Session.SessionNotAfterMS)
		if err != nil {
			t.Fatal(err)
		}
		h.Admission[0].Initial.Deadline = deadline
		constructionDeadlines = append(constructionDeadlines, deadline)
	}
	time.Sleep(30 * time.Millisecond)
	for index := range 2 {
		if err := constructionDeadlines[index].Check(); !errors.Is(err, timev4.ErrExpired) {
			t.Fatal("construction deadline did not expire", err)
		}
		pair, err := owner.Connect(ctx)
		if err != nil {
			t.Fatal("prepared original client was canceled or recreated", err)
		}
		payload := []byte("original-aggregate-capacity")
		got, callErr := pair.CallEcho(ctx, payload)
		closeErr := pair.Close()
		if callErr != nil || closeErr != nil || !bytes.Equal(got, payload) {
			t.Fatalf("original aggregate echo = %q, call=%v, cleanup=%v", got, callErr, closeErr)
		}
		if err := constructionDeadlines[index].Check(); !errors.Is(err, timev4.ErrExpired) {
			t.Fatal("Connect renewed an existing operation deadline", err)
		}
	}
	if _, err := owner.Connect(ctx); err == nil {
		t.Fatal("consumed original aggregate reinstalled a native client")
	}
}
