package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCaseContextInheritsParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	caseCtx, cancelCase := newCaseContext(parent, time.Minute)
	defer cancelCase()
	want := errors.New("collector canceled")
	cancelParent(want)
	select {
	case <-caseCtx.Done():
		if !errors.Is(context.Cause(caseCtx), want) {
			t.Fatalf("case context cause = %v, want %v", context.Cause(caseCtx), want)
		}
	case <-time.After(time.Second):
		t.Fatal("case context ignored parent cancellation")
	}
}

func TestCellContextInheritsParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancelCause(context.Background())
	cellCtx, cancelCell := newCellContext(parent, time.Minute)
	defer cancelCell()
	want := errors.New("fail-fast canceled sibling cell")
	cancelParent(want)
	select {
	case <-cellCtx.Done():
		if !errors.Is(context.Cause(cellCtx), want) {
			t.Fatalf("cell context cause = %v, want %v", context.Cause(cellCtx), want)
		}
	case <-time.After(time.Second):
		t.Fatal("cell context ignored parent cancellation")
	}
}
