package flowersec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestV4SessionLifecycleForwardsOriginalOwners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	info := protocolv4.V4SessionInfo{ApplicationProfile: protocolv4.V4ApplicationProfileTransport, SelectedFeatures: 3}
	operation := &sessionv4.DrainOperation{}
	drains := 0
	s := &V4Session{
		info: func() protocolv4.V4SessionInfo { return info },
		drain: func(timeout, cap uint64) (*sessionv4.DrainOperation, error) {
			drains++
			if timeout != 1234 || cap != 0 {
				t.Fatal("public drain changed the original duration or invented an absolute deadline")
			}
			return operation, nil
		},
		rekey: func(got context.Context) error {
			if got != ctx {
				t.Fatal("rekey replaced original caller context")
			}
			return nil
		},
		probeLiveness: func(got context.Context, timeout uint64) (sessionv4.ProbeResult, error) {
			if got != ctx || timeout != 1<<63 {
				t.Fatal("probe narrowed uint64 duration or replaced caller context")
			}
			return sessionv4.ProbeResult{Submitted: true, Complete: true, ElapsedAvailable: true, ElapsedMS: 91}, nil
		},
		waitTermination: func(got context.Context) error {
			if got != ctx {
				t.Fatal("termination replaced caller context")
			}
			return errors.New("private provider endpoint secret")
		},
	}
	if s.Info() != info || s.Rekey(ctx) != nil {
		t.Fatal("public facade did not expose original facts")
	}
	if err := s.Drain(1234); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(9999); err != nil || drains != 1 || s.drainOperation != operation {
		t.Fatal("repeated Drain replaced original operation", err, drains)
	}
	probe, err := s.ProbeLiveness(ctx, 1<<63)
	if err != nil || !probe.Submitted || !probe.Complete || !probe.ElapsedAvailable || probe.ElapsedMilliseconds != 91 || probe.Cause != nil {
		t.Fatal(probe, err)
	}
	if err := s.WaitTermination(ctx); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("termination did not redact provider details", err)
	}
	cancel()
	if result, err := s.WaitDrain(ctx); !errors.Is(err, context.Canceled) || result.Outcome != V4DrainPending {
		t.Fatal("canceled drain observer changed original operation", result, err)
	}
	_ = s.Close()
	if s.Info() != info {
		t.Fatal("Close erased detached READY information")
	}
}

func TestV4SessionProbePreservesRekeyInterruptionFacts(t *testing.T) {
	s := &V4Session{probeLiveness: func(context.Context, uint64) (sessionv4.ProbeResult, error) {
		return sessionv4.ProbeResult{Submitted: true, Cause: sessionv4.ErrProbeRekey}, sessionv4.ErrProbeRekey
	}}
	result, err := s.ProbeLiveness(context.Background(), 100)
	var failure *SessionError
	if !errors.As(err, &failure) || failure.Code() != V4SessionRekeyInProgress || !result.Submitted || result.ElapsedAvailable || result.Cause == nil || result.Cause.Code() != failure.Code() {
		t.Fatal("rekey interruption lost submission or availability facts", result, err)
	}
}
