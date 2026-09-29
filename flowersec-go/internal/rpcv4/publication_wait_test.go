package rpcv4

import (
	"context"
	"errors"
	"testing"
)

func TestPublicationWaitCancellationKeepsOriginalDecision(t *testing.T) {
	publication := &Publication{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	progress, err := publication.Wait(ctx)
	if !errors.Is(err, context.Canceled) || progress.Terminal || publication.Progress().Terminal {
		t.Fatal("observer cancellation changed original publication", progress, err)
	}
	publication.update(true, true, false, false, "")
	if publication.Progress().Flushed {
		t.Fatal("local acceptance reported a carrier handoff")
	}
	publication.update(false, false, true, true, "")
	progress, err = publication.Wait(context.Background())
	if err != nil || !progress.Flushed || !progress.Terminal {
		t.Fatal(progress, err)
	}
	publication.update(false, false, false, true, "owner_unavailable")
	if !publication.Progress().Flushed {
		t.Fatal("late carrier failure erased publication")
	}
}

func TestPublicationWaitPreservesSupersededBusinessResponse(t *testing.T) {
	publication := &Publication{}
	publication.update(false, false, false, true, "response_superseded")
	publication.update(true, true, true, true, "")
	progress, err := publication.Wait(context.Background())
	if err != nil || progress.Flushed || progress.Reason != "response_superseded" {
		t.Fatal(progress, err)
	}
}
