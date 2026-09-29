package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestV4ReadProjectionPreservesCancellationAndDetachedFacts(t *testing.T) {
	target := uint64(17)
	cause := protocolv4.V4ReadCauseUnexpectedEof
	wire := protocolv4.V4ReadResult{Progress: protocolv4.V4ReadProgress{Offset: 9, Target: &target}, WaitStatus: protocolv4.V4WaitStatusWaitCanceled, StreamStatus: protocolv4.V4StreamStatusEof, Cause: &cause}
	got := publicReadResult(wire, context.Canceled)
	target = 18
	if got.WaitStatus != wire.WaitStatus || got.StreamStatus != wire.StreamStatus || got.Progress.Offset != 9 || got.Progress.Target == nil || *got.Progress.Target != 17 || got.Cause == nil || *got.Cause != cause {
		t.Fatal("public projection lost facts or retained mutable metadata", got)
	}
}

func TestV4PublicationWaitAndTransferCannotInventFlush(t *testing.T) {
	publication := newResponsePublication(&rpcv4.Publication{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status, err := publication.Wait(ctx)
	if !errors.Is(err, context.Canceled) || status.State != PublicationPending || status.Cause != nil {
		t.Fatal(status, err)
	}
	if err := publication.TransferTo(struct{}{}); err == nil {
		t.Fatal("unadmitted maintenance owner was accepted")
	}
	if publication.State().State != PublicationPending {
		t.Fatal("transfer or wait changed publication")
	}
	for _, reason := range []string{"response_superseded", "response_aborted", "owner_unavailable", "deadline", "publish_failed"} {
		state := publicationStatus(rpcv4.PublicationProgress{Terminal: true, Reason: reason})
		if state.State != PublicationUnknown || state.Cause == nil || string(*state.Cause) != reason {
			t.Fatal(state)
		}
	}
}

func TestV4OwnerlessLifecycleCannotClaimCleanup(t *testing.T) {
	session := newV4SessionFromEnvironment(nil)
	if session.CleanupStatus().Complete || session.WaitCleanup(context.Background()) == nil {
		t.Fatal("Session invented cleanup")
	}
	subscription := newNotificationSubscription(nil)
	subscription.Close()
	if subscription.CleanupStatus().Complete || subscription.WaitClosed(context.Background()) == nil {
		t.Fatal("subscription invented cleanup")
	}
	serve := newServeHandle(nil)
	serve.Close()
	if serve.CleanupStatus().Complete || serve.WaitCleanup(context.Background()) == nil || serve.Drain() == nil {
		t.Fatal("serve invented cleanup")
	}
}

func TestV4SessionCleanupStatusPreservesOriginalFacts(t *testing.T) {
	original := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStateCleanupIncomplete, CoreCleanup: protocolv4.V4CoreCleanupComplete, PendingCallbacks: 2}
	s := &V4Session{cleanupStatus: func() protocolv4.V4CleanupStatus { return original }}
	status := s.CleanupStatus()
	if status.Complete || !status.CleanupIncomplete || status.PendingCallbacks != 2 || status.CoreCleanup != original.CoreCleanup || !errors.Is(sessionv4.ErrSessionCleanupIncomplete, ErrCleanupIncomplete) {
		t.Fatal("public Session status lost original cleanup facts", status)
	}
	original = protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
	if status := s.CleanupStatus(); !status.Complete || status.CleanupIncomplete || status.PendingCallbacks != 0 {
		t.Fatal("public status failed to converge after physical cleanup", status)
	}
}

func TestV4ReadInProgressUsesOriginalIdentity(t *testing.T) {
	if !errors.Is(sessionv4.ErrReadInProgress, ErrReadInProgress) {
		t.Fatal("the public read-in-progress sentinel does not identify the original error")
	}
}

func TestV4OpenStreamPreservesCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newV4SessionFromOwnerFactory(func(got context.Context, _ string, _ []byte, _ *timev4.Deadline) (*sessionv4.StreamOwnership, error) {
		if got != ctx {
			t.Fatal("OpenStream replaced the caller's cancellation context")
		}
		return nil, got.Err()
	}, nil)
	if _, err := s.OpenStream(ctx, "example/raw", StreamMetadata{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
