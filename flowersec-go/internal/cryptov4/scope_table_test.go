package cryptov4

import (
	"errors"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestScopeTableCollisionDeletionAndFixedBacking(t *testing.T) {
	for removeAt := range 6 {
		table, err := newScopeTable(6)
		if err != nil {
			t.Fatal(err)
		}
		var scopes [6]uint64
		var owners [6]scopeKeys
		for candidate, count := uint64(0), 0; count < len(scopes); candidate++ {
			if table.bucket(candidate) == len(table.slots)-1 {
				scopes[count] = candidate
				count++
			}
		}
		for i, scope := range scopes {
			if err := table.insert(scope, &owners[i]); err != nil {
				t.Fatal(err)
			}
		}
		if err := table.insert(scopes[0], &scopeKeys{}); !errors.Is(err, ErrScope) || table.get(scopes[0]) != &owners[0] {
			t.Fatal("duplicate replaced original owner", err)
		}
		if err := table.insert(math.MaxUint64, &scopeKeys{}); !errors.Is(err, ErrCapacity) || table.count != len(scopes) {
			t.Fatal("full table mutated or grew", err)
		}
		table.remove(scopes[removeAt])
		for i, scope := range scopes {
			want := &owners[i]
			if i == removeAt {
				want = nil
			}
			if table.get(scope) != want {
				t.Fatal("wrapped deletion broke a search path", removeAt, i)
			}
		}
		if allocations := testing.AllocsPerRun(1000, func() {
			if table.insert(scopes[removeAt], &owners[removeAt]) != nil {
				panic("fixed table lost capacity")
			}
			for scope, owner := range table.all() {
				if table.get(scope) != owner {
					panic("fixed table lost identity")
				}
			}
			table.remove(scopes[removeAt])
		}); allocations != 0 {
			t.Fatal("index churn allocated backing", allocations)
		}
	}
}

func TestScopeTableChurnAgainstReference(t *testing.T) {
	table, err := newScopeTable(37)
	if err != nil {
		t.Fatal(err)
	}
	original := &table.slots[0]
	want := make(map[uint64]*scopeKeys)
	rng := rand.New(rand.NewPCG(1, 2))
	var owners [128]scopeKeys
	for i := range 10000 {
		scope := rng.Uint64N(128)
		if i%127 == 0 {
			scope = protocolv4.DatagramScope()
		}
		if rng.Uint64N(2) == 0 {
			table.remove(scope)
			delete(want, scope)
		} else {
			owner := &owners[scope%uint64(len(owners))]
			err := table.insert(scope, owner)
			switch {
			case want[scope] != nil:
				if !errors.Is(err, ErrScope) {
					t.Fatal("duplicate", err)
				}
			case len(want) == table.limit:
				if !errors.Is(err, ErrCapacity) {
					t.Fatal("capacity", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				want[scope] = owner
			}
		}
		if table.count != len(want) || &table.slots[0] != original {
			t.Fatal("index grew or lost entries")
		}
		for scope, owner := range want {
			if table.get(scope) != owner {
				t.Fatal("index lost original owner", i, scope)
			}
		}
		for scope, owner := range table.all() {
			if want[scope] != owner {
				t.Fatal("index retained a removed owner", i, scope)
			}
		}
	}
}

func TestScopeTableCapacityUsesActualCoexistingOwners(t *testing.T) {
	for _, test := range []struct {
		config Config
		want   int
	}{
		{Config{}, 1},
		{Config{Datagrams: true}, 2},
		{Config{MaxScopes: 7, WorkSlots: 4}, 8},
		{Config{MaxScopes: 7, PendingScopes: 2, WorkSlots: 4, Datagrams: true}, 15},
		{Config{ApplicationProfile: "services", MaxScopes: 1}, 2},
	} {
		got, err := scopeTableCapacity(test.config)
		if err != nil || got != test.want {
			t.Fatal(test.config, got, err)
		}
	}
	for _, limit := range []int{0, -1, math.MaxInt, math.MaxInt / 2} {
		if _, err := scopeTableSlots(limit); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unrepresentable index accepted", limit, err)
		}
	}
}

func TestScopeTablePendingOverflowSurvivesPacketReleaseAndStage(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server, _ := enginePair(t, profile, func(c *Config) {
				c.PendingScopes = 2
				c.MaxScopes, c.SignedMaxScopes = 8, 8
			})
			// Fill the server's complete positive capacity first.
			for scope := uint64(2); scope <= 14; scope += 2 {
				if err := server.OpenScope(scope); err != nil {
					t.Fatal(err)
				}
			}
			pendingCap := server.config.PendingScopes + server.config.WorkSlots
			var incoming []*IncomingScope
			for i := uint32(0); i < pendingCap; i++ {
				scope := uint64(3 + 2*i)
				if err := client.OpenLocalScope(scope); err != nil {
					t.Fatal(err)
				}
				wire := sealed(t, client, protocolv4.FrameOpenStream, scope, nil)
				p, owner, err := server.OpenIncoming(wire, acceptRecord)
				if err != nil {
					t.Fatal("index omitted pending rejection overflow", err)
				}
				p.Release()
				incoming = append(incoming, owner)
			}
			if server.current.keys.count != server.current.keys.limit || server.pending != pendingCap || server.borrowedWork != 0 {
				t.Fatal("fixture did not fill independent pending and positive owners")
			}
			if err := server.StageEpoch([32]byte{9}, cryptoSample(t, server)); err != nil {
				t.Fatal("full index could not reserve its original staged copy", err)
			}
			for _, owner := range incoming {
				if err := owner.Resolve(false); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.CommitEpoch(); err != nil {
				t.Fatal(err)
			}
			if server.current.keys.count != int(server.config.MaxScopes)+2 {
				t.Fatal("rejected owners survived epoch recycling")
			}
		})
	}
}

func TestScopeTableReusesOnlyDetachedEpochIndexes(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			e, _, _ := enginePair(t, profile)
			first, second := &e.current.keys.slots[0], &e.spareScopes.slots[0]
			jobs := &e.stageJobs[0]
			packet, err := e.Seal(protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("old epoch tail"))
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			old := packet.epoch
			for range 3 {
				if err := e.StageEpoch([32]byte{9}, cryptoSample(t, e)); err != nil {
					t.Fatal(err)
				}
				if err := e.CommitEpoch(); err != nil {
					t.Fatal(err)
				}
				if old.keys.slots != nil || &e.stageJobs[0] != jobs ||
					(&e.current.keys.slots[0] != first && &e.current.keys.slots[0] != second) ||
					(&e.spareScopes.slots[0] != first && &e.spareScopes.slots[0] != second) {
					t.Fatal("epoch retained or enlarged index backing")
				}
				if _, err := packet.Bytes(); !errors.Is(err, ErrEpoch) {
					t.Fatal("recycled table reopened old packet", err)
				}
			}
			e.Close()
			requireEngineCleanupPending(t, e)
			packet.Release()
			requireEngineCleanup(t, e)
			if e.stageJobs != nil || e.spareScopes.slots != nil || e.current.keys.slots != nil {
				t.Fatal("closed engine retained indexes or stage jobs")
			}
		})
	}
}

func TestScopeTableFailedStageKeepsOriginalBackingAndUsage(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			e, _, _ := enginePair(t, profile)
			spare, current, jobs := &e.spareScopes.slots[0], &e.current.keys.slots[0], &e.stageJobs[0]
			before := e.derivations
			e.derivations = e.limits.Derivations - 1
			if err := e.StageEpoch([32]byte{9}, cryptoSample(t, e)); !errors.Is(err, ErrUsage) {
				t.Fatal("stage did not preflight its complete KDF charge", err)
			}
			if &e.spareScopes.slots[0] != spare || e.derivations != e.limits.Derivations-1 || e.staged != nil {
				t.Fatal("refused stage consumed a candidate or reset KDF usage")
			}
			e.derivations = before
			algorithm := e.profile.Algorithm
			e.profile.Algorithm = "unavailable-test-provider"
			if err := e.StageEpoch([32]byte{9}, cryptoSample(t, e)); !errors.Is(err, ErrConfiguration) {
				t.Fatal("expected actual key construction failure", err)
			}
			e.profile.Algorithm = algorithm
			if &e.spareScopes.slots[0] != spare || &e.current.keys.slots[0] != current || &e.stageJobs[0] != jobs || e.derivations <= before || e.staged != nil || e.staging {
				t.Fatal("failed KDF lost original index or refunded irreversible work")
			}
			for _, job := range e.stageJobs {
				if job.owner != nil {
					t.Fatal("failed stage kept an obsolete key owner")
				}
			}
			if err := e.StageEpoch([32]byte{9}, cryptoSample(t, e)); err != nil {
				t.Fatal("failed stage lost reusable index", err)
			}
			if err := e.CommitEpoch(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
