package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestRekeyTimingOriginalThreeStages(t *testing.T) {
	c, now := testCredit(t, protocolv4.ClientToServer)
	timing, err := newRekeyTiming(c, RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	now.Milliseconds = 4000
	if err = timing.Init(); err != nil {
		t.Fatal(err)
	}
	now.Milliseconds = 9000
	if err = timing.Commit(); err != nil {
		t.Fatal(err)
	}
	if timing.anchor.Milliseconds != 9000 {
		t.Fatal("commit did not own confirmation origin")
	}
	if err = timing.Commit(); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("duplicate commit refreshed deadline", err)
	}
	now.Milliseconds = 38000
	if err = timing.Ack(); err != nil {
		t.Fatal("prepare and confirm were collapsed", err)
	}
}

func TestRekeyTimingExpirationAndNoRefresh(t *testing.T) {
	for _, phase := range []string{"local", "protocol", "confirm"} {
		t.Run(phase, func(t *testing.T) {
			c, now := testCredit(t, protocolv4.ClientToServer)
			timing, err := newRekeyTiming(c, RekeyPhaseBudgets{5000, 10000, 30000})
			if err != nil {
				t.Fatal(err)
			}
			var counts diagnosticv4.Counters
			timing.startDiagnostics(&counts)
			if phase != "local" {
				if err = timing.Init(); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "confirm" {
				if err = timing.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			limits := map[string]uint64{"local": 5000, "protocol": 10000, "confirm": 30000}
			now.Milliseconds = limits[phase]
			for range 3 {
				if err = timing.Check(); !errors.Is(err, cryptov4.ErrExpired) {
					t.Fatal("wait refreshed deadline", err)
				}
			}
			if phase != "local" {
				_ = timing.checkPhase()
			}
			if got := counts.Snapshot(diagnosticv4.MetricRekeyTimeout); got.Total != 1 || got.Phase[timing.diagnosticPhase()] != 1 {
				t.Fatal("repeated phase checks changed timeout count", got)
			}
			if timing.anchor.Milliseconds != 0 {
				t.Fatal("expired anchor moved")
			}
		})
	}
	c, now := testCredit(t, protocolv4.ServerToClient)
	timing, err := newRekeyTiming(c, RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	now.Milliseconds = 60000
	if err = timing.Init(); err != nil {
		t.Fatal("server acquired a client local-prepare deadline", err)
	}
	now.Milliseconds = 70000
	if err = timing.Commit(); !errors.Is(err, cryptov4.ErrExpired) {
		t.Fatal(err)
	}
}
