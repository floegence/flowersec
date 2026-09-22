package cryptov4

import (
	"errors"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestScopeKeyWorkCannotBorrowMaintenanceOrUnboundedBacking(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519, func(c *Config) { c.PendingScopes = 2 })
	if err := client.OpenLocalScope(3); err != nil {
		t.Fatal(err)
	}
	wire := sealed(t, client, protocolv4.FrameOpenStream, 3, nil)
	var held []*Packet
	for range server.config.WorkSlots {
		p, err := server.Seal(protocolv4.FrameStreamData, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, p)
	}
	before := server.derivations
	if _, _, err := server.OpenIncoming(wire, acceptRecord); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded incoming key work", err)
	}
	if err := server.OpenLocalScope(2); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded local key work", err)
	}
	if server.derivations != before || server.pending != 0 || !server.unusedScope(3) || !server.unusedScope(2) {
		t.Fatal("failed work admission mutated scope/KDF accounting")
	}
	ping, err := server.Seal(protocolv4.FramePing, 0, nil)
	if err != nil {
		t.Fatal("scope jobs borrowed reserved maintenance work", err)
	}
	ping.Release()
	for _, p := range held {
		p.Release()
	}
	p, incoming, err := server.OpenIncoming(wire, acceptRecord)
	if err != nil {
		t.Fatal(err)
	}
	p.Release()
	if err = incoming.Resolve(true); !errors.Is(err, ErrNotReady) {
		t.Fatal("outcome performed implicit crypto", err)
	}
	if err = incoming.PrepareAccept(); err != nil {
		t.Fatal(err)
	}
	after := server.derivations
	if err = incoming.PrepareAccept(); err != nil || server.derivations != after {
		t.Fatal("prepared original key derived twice", err)
	}
	if _, err = server.Seal(protocolv4.FrameStreamData, 3, nil); !errors.Is(err, ErrNotReady) {
		t.Fatal("prepared key selected an outcome", err)
	}
	if err = incoming.Resolve(true); err != nil || server.derivations != after {
		t.Fatal("outcome derived instead of transferring original key", err)
	}
}

func TestScopeKeyWorkAcceptanceAcrossConcurrentStage(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			for range 32 {
				client, server, _ := enginePair(t, profile, func(c *Config) { c.PendingScopes = 2 })
				if err := client.OpenLocalScope(3); err != nil {
					t.Fatal(err)
				}
				wire := sealed(t, client, protocolv4.FrameOpenStream, 3, nil)
				packet, incoming, err := server.OpenIncoming(wire, acceptRecord)
				if err != nil {
					t.Fatal(err)
				}
				packet.Release()
				start := make(chan struct{})
				prepared, staged := make(chan error, 1), make(chan error, 1)
				go func() { <-start; prepared <- incoming.PrepareAccept() }()
				born := cryptoSample(t, server)
				go func() { <-start; staged <- server.StageEpoch([32]byte{9}, born) }()
				close(start)
				if err = <-prepared; err != nil {
					t.Fatal(err)
				}
				if err = <-staged; err != nil {
					t.Fatal(err)
				}
				if err = incoming.Resolve(true); err != nil {
					t.Fatal(err)
				}
				if err = client.AcceptLocalScope(3); err != nil {
					t.Fatal(err)
				}
				if err = client.StageEpoch([32]byte{9}, cryptoSample(t, client)); err != nil {
					t.Fatal(err)
				}
				for _, e := range []*Engine{client, server} {
					if err = e.CommitEpoch(); err != nil {
						t.Fatal(err)
					}
				}
				wire = sealed(t, server, protocolv4.FrameStreamData, 3, []byte("prepared across stage"))
				packet, _, header, err := client.Open(wire, acceptRecord)
				if err != nil || header.Epoch != 1 || header.Sequence != 0 {
					t.Fatal("staging lost original accepted send key", header, err)
				}
				packet.Release()
			}
		})
	}
}

func TestScopeKeyWorkCloseAndRetireCannotInstallLateKeys(t *testing.T) {
	for _, action := range []string{"close", "retire"} {
		t.Run(action, func(t *testing.T) {
			for range 48 {
				e, _, _ := enginePair(t, protocolv4.DHProfileX25519)
				start := make(chan struct{})
				var wg sync.WaitGroup
				wg.Add(2)
				var result error
				go func() { defer wg.Done(); <-start; result = e.OpenLocalScope(3) }()
				go func() {
					defer wg.Done()
					<-start
					if action == "close" {
						e.Close()
					} else {
						e.RetireScope(3)
					}
				}()
				close(start)
				wg.Wait()
				if result != nil && !errors.Is(result, ErrClosed) && !errors.Is(result, ErrScope) && !errors.Is(result, ErrTransition) {
					t.Fatal(result)
				}
				e.mu.Lock()
				if e.flight != 0 || e.reliableFlight != 0 || action == "close" && e.current.keys.count != 0 || action == "retire" && result != nil && e.current.keys.get(3) != nil {
					t.Fatal("late key job retained authority or work charge")
				}
				e.mu.Unlock()
				if action == "close" {
					requireEngineCleanup(t, e)
				}
			}
		})
	}
}
