package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestApplicationPresetKeepsProtectedServiceAndResidentFloor(t *testing.T) {
	for _, profile := range []ApplicationResourceProfile{ApplicationProfileClient, ApplicationProfileServer, ApplicationProfileConstrained} {
		for _, execution := range []bool{false, true} {
			c, err := ApplicationExecutorPreset(profile, 8192, 65536, execution, true)
			if err != nil {
				t.Fatal(profile, execution, err)
			}
			charge, err := ApplicationExecutorCharge(c)
			if err != nil {
				t.Fatal(err)
			}
			ordinary, resident, err := c.profileServiceBytes()
			if err != nil || c.CompletionRunning != 2 || c.CompletionReserved != 4096 || c.DisableManagement == execution {
				t.Fatal(c, err)
			}
			if profile == ApplicationProfileConstrained {
				if c.Running != 8 || c.Ready != 16 || c.ResidentRunning != 6 || c.ResidentReady != 12 || ordinary != 3*1048576 || resident != 5*1048576/2 {
					t.Fatal(c, ordinary, resident)
				}
			} else if c.Running != 26 || c.Ready != 52 || c.ResidentRunning != 18 || c.ResidentReady != 36 || ordinary != 7*1048576 || resident != 6*1048576 {
				t.Fatal(c, ordinary, resident)
			}
			workers := uint64(c.Running + 2 + 1 + 2)
			if execution {
				workers += 2
			}
			if charge[resourcev4.Tasks] != workers || charge[resourcev4.WorkSlots] != workers {
				t.Fatal("root did not admit the actual enabled shared workers", charge, workers)
			}
			if completion := (&ApplicationExecutor{config: c}).CompletionCharge(); completion[resourcev4.SDKBytes] > 256 || completion[resourcev4.Tasks] != 0 || completion[resourcev4.WorkSlots] != 0 {
				t.Fatal("dormant descriptor acquired a worker or exceeded its own metadata bound", completion)
			}
			bad := c
			bad.ResidentRunning = bad.Running
			if _, err := ApplicationExecutorCharge(bad); !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal("preset erased the short service floor", err)
			}
			bad = c
			bad.RuntimeBytesPerTask = 256 * 1024
			if _, err := ApplicationExecutorCharge(bad); !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal("oversized qualified Completion stacks were accepted", err)
			}
		}
	}
}

func TestApplicationCodecAllocationBelongsToOriginalReceiveVector(t *testing.T) {
	config := typedResultConfig(t)
	direction, _, err := config.Definition.Directions(false)
	if err != nil {
		t.Fatal(err)
	}
	f := newExecutorFixture(t, 2, 1)
	delegates := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 8192, resourcev4.Items: 1})
	codec, err := ApplicationMessageCodecWithOptions(direction,
		func(_ context.Context, _ any) ([]byte, error) { return nil, nil },
		func(_ context.Context, _ []byte) (any, error) { return nil, nil },
		ApplicationMessageCodecOptions{Delegates: delegates, ApplicationBytes: 32768, Execution: MessageCodecIndependent})
	if err != nil {
		t.Fatal(err)
	}
	charged, err := typedMessageDecodeCharge(codec, 17, 8192)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := BytesMessageCodec(direction)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := typedMessageDecodeCharge(plain, 17, 8192)
	if err != nil || charged[resourcev4.SDKBytes]-baseline[resourcev4.SDKBytes] != 32768 {
		t.Fatal("opaque codec allocation was missing from the complete input vector", baseline, charged, err)
	}
}

func TestCompletionReadyUsesOnlyFourOriginalEligibleOwners(t *testing.T) {
	e := &ApplicationExecutor{completions: make([]completionSlot, 12)}
	for i := range e.completions {
		e.completions[i] = completionSlot{active: true, submitted: true, order: uint64(12 - i)}
	}
	e.refillCompletionReadyLocked()
	if e.completionReadyCount != 4 {
		t.Fatal("all eligible owners became queued jobs", e.completionReadyCount)
	}
	for i, index := range e.completionReady {
		if index != 11-i {
			t.Fatal("ready admission lost original owner fairness", e.completionReady)
		}
	}
	e.completions[0].claimed = true
	e.refillCompletionReadyLocked()
	if e.completionReady[0] != 0 || e.completionReadyCount != 4 {
		t.Fatal("Completion ancestor's original promise waited behind unclaimed jobs", e.completionReady)
	}
	e.completions[0].running = true
	e.refillCompletionReadyLocked()
	if e.completionReady[0] != 11 || e.completionReadyCount != 4 {
		t.Fatal("actual running work also occupied a ready position", e.completionReady)
	}
}
