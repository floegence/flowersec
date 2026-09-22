package cryptov4

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestEpochStageHasOriginalReservedWorkPosition(t *testing.T) {
	e, _, _ := enginePair(t, protocolv4.DHProfileX25519)
	var held []*Packet
	for range e.config.WorkSlots {
		p, err := e.Seal(protocolv4.FrameStreamData, 1, []byte("real provider tail"))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, p)
	}
	if err := e.StageEpoch([32]byte{9}, cryptoSample(t, e)); err != nil {
		t.Fatal("ordinary output borrowed rekey work", err)
	}
	if err := e.CommitEpoch(); !errors.Is(err, ErrTransition) {
		t.Fatal("old publication tail bypassed", err)
	}
	for _, p := range held {
		if _, err := p.Bytes(); err != nil {
			t.Fatal("staging invalidated original tail", err)
		}
		p.Release()
	}
	if err := e.CommitEpoch(); err != nil {
		t.Fatal(err)
	}
}

func TestEpochStageCloseCannotPublishLateKeys(t *testing.T) {
	for range 12 {
		var e *Engine
		now := time.Now()
		started := make(chan struct{})
		var once sync.Once
		clock := cryptoClock(t, func() time.Time {
			if e != nil && e.staging {
				once.Do(func() { close(started) })
			}
			return now
		})
		e, _ = enginePairWithClock(t, protocolv4.DHProfileP256, clock, func(c *Config) { c.MaxScopes, c.SignedMaxScopes = 128, 128 })
		for scope := uint64(3); scope < 257; scope += 2 {
			if err := e.OpenScope(scope); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		born := cryptoSample(t, e)
		go func() { done <- e.StageEpoch([32]byte{8}, born) }()
		select {
		case <-started:
		case err := <-done:
			t.Fatal("stage exited before owning its job", err)
		}
		e.Close()
		if err := <-done; err != nil && !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		e.mu.Lock()
		if e.staging || e.flight != 0 || e.staged != nil && (e.staged.root != ([32]byte{}) || e.staged.keys.count != 0) {
			t.Fatal("late stage survived close")
		}
		e.mu.Unlock()
		requireEngineCleanup(t, e)
		if err := e.CommitEpoch(); !errors.Is(err, ErrClosed) {
			t.Fatal("closed stage installed", err)
		}
	}
}
