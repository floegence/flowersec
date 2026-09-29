package ledgerv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type topUpTerminalReceipt struct{ expected TopUpServerSnapshot }

func (e topUpTerminalReceipt) CheckTopUpTerminal(_ SQLiteIdentity, r protocolv4.TopUpRequestFacts, s TopUpServerSnapshot) error {
	if s != e.expected || r != s.Request {
		return ErrOwner
	}
	return nil
}
func newTerminalClient(t *testing.T, server *topUpServerFixture) (*sqliteFixture, *SQLiteTopUpJournal, SQLiteTopUpConfig) {
	t.Helper()
	f := newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 128, MaxRecords: 16, MaxRecordBytes: 131072, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})
	owner := &topUpOwner{}
	owner.generation.Store(1)
	c := SQLiteTopUpConfig{Tenant: "tenant-1", Source: [16]byte{1}, BindingGeneration: 1, IdentityBytes: 1024, KeyReferenceBytes: 128, PoolBytes: 1 << 18, Clock: server.clock, Authority: owner}
	charge, err := SQLiteTopUpJournalCharge(f.backing.limits, c)
	if err != nil {
		t.Fatal(err)
	}
	j, err := CreateSQLiteTopUpJournal(context.Background(), f.backing, f.identity, f.continuity, c, f.reserve(charge, 1), f.environment)
	if j != nil {
		f.stores = append(f.stores, j.store)
	}
	if err != nil {
		t.Fatal(err)
	}
	return f, j, c
}
func TestSQLiteTopUpTerminalRecoveryDoesNotInstallOrAdvanceLocalMaterial(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "installed"}[installed], func(t *testing.T) {
			server := newTopUpServerFixture(t)
			client, j, c := newTerminalClient(t, server)
			ctx := context.Background()
			certificate := []byte{0xa0}
			identity, e := protocolv4.TopUpIdentityDigest(certificate)
			if e != nil {
				t.Fatal(e)
			}
			r, _ := server.request(1, 1)
			r.Identity = identity
			r, wire := serverTopUpRequest(t, r, 9000)
			if e = j.Begin(ctx, r, certificate, []byte("original-key")); e != nil {
				t.Fatal(e)
			}
			if _, e = server.prepare(wire); e != nil {
				t.Fatal(e)
			}
			response, _ := serverTopUpResponse(t, r, 1, false, 0)
			if _, e = server.server.Commit(ctx, server.authority, wire, response); e != nil {
				t.Fatal(e)
			}
			frontier := uint64(0)
			if installed {
				codec, _ := protocolv4.NewTopUpCodec()
				batch, e := codec.ParseResponse(response, r)
				if e != nil {
					t.Fatal(e)
				}
				e = j.Install(ctx, r, batch)
				batch.Release()
				if e != nil {
					t.Fatal(e)
				}
				frontier = 2
			}
			server.tick.Store(1010)
			terminal, e := server.server.AdvanceRetirement(ctx, server.authority)
			if e != nil {
				t.Fatal(e)
			}
			// An unauthenticated value never becomes authoritative by matching fields.
			if e = j.ConfirmTerminal(ctx, r, terminal, nil); !errors.Is(e, ErrConfiguration) {
				t.Fatal("missing receipt", e)
			}
			if e = j.ConfirmTerminal(ctx, r, terminal, topUpTerminalReceipt{}); e == nil {
				t.Fatal("forged receipt")
			}
			evidence := topUpTerminalReceipt{terminal}
			original := j.store.execer
			fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost terminal commit") }}
			fault.commits.Store(1)
			j.store.execer = fault
			if e = j.ConfirmTerminal(ctx, r, terminal, evidence); !errors.Is(e, ErrUnknown) {
				t.Fatal("terminal commit uncertainty", e)
			}
			j.store.execer = original
			closeSQLite(t, j.store)
			charge, e := SQLiteTopUpJournalCharge(client.backing.limits, c)
			if e != nil {
				t.Fatal(e)
			}
			j, e = OpenSQLiteTopUpJournal(ctx, client.backing, client.identity, client.continuity, c, client.reserve(charge, 1), client.environment)
			if j != nil {
				client.stores = append(client.stores, j.store)
			}
			if e != nil {
				t.Fatal(e)
			}
			recovered, e := j.Recover(ctx)
			if e != nil || recovered.State != TopUpJournalTerminal || recovered.Terminal != terminal || recovered.ArtifactFrontier != frontier || recovered.RetiredSequence != 1 {
				t.Fatal("terminal recovery altered local facts", recovered, e)
			}
			count, e := j.store.scalar("SELECT count(*) FROM pool")
			if e != nil || count != int64(frontier) {
				t.Fatal("terminal installed or removed material", count, e)
			}
			if e = j.ConfirmTerminal(ctx, r, terminal, evidence); e != nil {
				t.Fatal("terminal replay", e)
			}
		})
	}
}

func TestSQLiteTopUpTerminalKeepsSequenceUntilServerRetires(t *testing.T) {
	server := newTopUpServerFixture(t)
	_, j, _ := newTerminalClient(t, server)
	ctx := context.Background()
	certificate := []byte{0xa0}
	identity, e := protocolv4.TopUpIdentityDigest(certificate)
	if e != nil {
		t.Fatal(e)
	}
	r, _ := server.request(1, 1)
	r.Identity = identity
	r, wire := serverTopUpRequest(t, r, 9000)
	if e = j.Begin(ctx, r, certificate, []byte("original-key")); e != nil {
		t.Fatal(e)
	}
	if _, e = server.prepare(wire); e != nil {
		t.Fatal(e)
	}
	terminal, e := server.server.Deny(ctx, server.authority, wire, protocolv4.V4TopUpErrorCodeCapacityExhausted)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.ConfirmTerminal(ctx, r, terminal, topUpTerminalReceipt{terminal}); e != nil {
		t.Fatal(e)
	}
	next, _ := server.request(2, 1)
	next.Identity = identity
	next.DeadlineMS = 3000
	next, _ = serverTopUpRequest(t, next, 9000)
	if e = j.Begin(ctx, next, certificate, []byte("original-key")); !errors.Is(e, ErrConflict) {
		t.Fatal("unretired terminal released next sequence", e)
	}
	server.tick.Store(410)
	retired, e := server.server.AdvanceRetirement(ctx, server.authority)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.ConfirmTerminal(ctx, r, retired, topUpTerminalReceipt{retired}); e != nil {
		t.Fatal("terminal retirement", e)
	}
	if e = j.Begin(ctx, next, certificate, []byte("original-key")); e != nil {
		t.Fatal("retired sequence not reusable", e)
	}
}

type topUpPermanentReceipt struct{ expected TopUpPermanentFenceReceipt }

func (e topUpPermanentReceipt) CheckTopUpPermanentFence(_ SQLiteIdentity, r TopUpPermanentFenceReceipt) error {
	if r != e.expected {
		return ErrOwner
	}
	return nil
}

func TestSQLiteTopUpPermanentFencePreservesUnknownAndAcknowledgedFacts(t *testing.T) {
	for _, originalState := range []TopUpJournalState{TopUpJournalPending, TopUpJournalInstalled, TopUpJournalAcked} {
		t.Run(map[TopUpJournalState]string{TopUpJournalPending: "never_sent", TopUpJournalInstalled: "installed", TopUpJournalAcked: "acked"}[originalState], func(t *testing.T) {
			server := newTopUpServerFixture(t)
			client, j, c := newTerminalClient(t, server)
			ctx := context.Background()
			certificate := []byte{0xa0}
			identity, e := protocolv4.TopUpIdentityDigest(certificate)
			if e != nil {
				t.Fatal(e)
			}
			r, _ := server.request(1, 1)
			r.Identity = identity
			r, wire := serverTopUpRequest(t, r, 9000)
			if e = j.Begin(ctx, r, certificate, []byte("original-key")); e != nil {
				t.Fatal(e)
			}
			var responseFacts protocolv4.TopUpResponseFacts
			frontier := uint64(0)
			if originalState != TopUpJournalPending {
				if _, e = server.prepare(wire); e != nil {
					t.Fatal(e)
				}
				response, facts := serverTopUpResponse(t, r, 1, false, 0)
				responseFacts = facts
				if _, e = server.server.Commit(ctx, server.authority, wire, response); e != nil {
					t.Fatal(e)
				}
				codec, _ := protocolv4.NewTopUpCodec()
				batch, e := codec.ParseResponse(response, r)
				if e != nil {
					t.Fatal(e)
				}
				e = j.Install(ctx, r, batch)
				batch.Release()
				if e != nil {
					t.Fatal(e)
				}
				frontier = 2
				if originalState == TopUpJournalAcked {
					ack := serverTopUpAck(t, r, facts, 1)
					if _, e = server.server.Ack(ctx, server.authority, ack); e != nil {
						t.Fatal(e)
					}
					if e = j.ConfirmAck(ctx, r, facts); e != nil {
						t.Fatal(e)
					}
				}
			}
			server.authority.permanent.Store(true)
			if _, e = server.server.AdvanceRetirement(ctx, server.authority); e != nil {
				t.Fatal(e)
			}
			receipt := TopUpPermanentFenceReceipt{Tenant: r.Tenant, Source: r.Source, Generation: 1}
			if e = j.ConfirmPermanentFence(ctx, receipt, topUpPermanentReceipt{}); e == nil {
				t.Fatal("untrusted source fence")
			}
			if e = j.ConfirmPermanentFence(ctx, receipt, topUpPermanentReceipt{receipt}); e != nil {
				t.Fatal(e)
			}
			closeSQLite(t, j.store)
			charge, e := SQLiteTopUpJournalCharge(client.backing.limits, c)
			if e != nil {
				t.Fatal(e)
			}
			j, e = OpenSQLiteTopUpJournal(ctx, client.backing, client.identity, client.continuity, c, client.reserve(charge, 1), client.environment)
			if j != nil {
				client.stores = append(client.stores, j.store)
			}
			if e != nil {
				t.Fatal(e)
			}
			recovered, e := j.Recover(ctx)
			want := TopUpJournalTerminal
			if originalState == TopUpJournalAcked {
				want = TopUpJournalAcked
			}
			if e != nil || recovered.State != want || recovered.PermanentFenceGeneration != 1 || recovered.ArtifactFrontier != frontier || recovered.Request != r || recovered.Response != responseFacts || recovered.Terminal != (TopUpServerSnapshot{}) || recovered.RetiredSequence != 1 {
				t.Fatal("permanent fence fabricated or dropped operation facts", recovered, e)
			}
			next, _ := server.request(2, 1)
			next.Identity = identity
			next.DeadlineMS = 3000
			next, _ = serverTopUpRequest(t, next, 9000)
			if e = j.Begin(ctx, next, certificate, []byte("original-key")); !errors.Is(e, ErrFenced) {
				t.Fatal("retired source incarnation reused", e)
			}
		})
	}
}
