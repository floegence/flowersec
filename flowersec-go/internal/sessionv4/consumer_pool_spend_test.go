package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestConsumerPoolOriginalSQLiteActivation(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	x, err := consumeSessionPool(t, f, a)
	if err != nil || x == nil || !a.committed || !a.activated {
		t.Fatal("original TxA-P did not activate", err)
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("activated twice", err)
	}
	if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("construction published credentials")
	}
}

func TestConsumerPoolRejectsRevokedActivationBeforeConsume(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	f.trust.trust.rejected.Store(true)
	if x, err := consumeSessionPool(t, f, a); err == nil || x != nil {
		t.Fatal("revoked activation consumed", err)
	}
	if a.claimed || a.committed || a.activated {
		t.Fatal("revocation crossed claim gate")
	}
}

type scheduledConsumerAuthority struct {
	poolSQLiteAuthority
	schedule func(context.Context) (func(), error)
	reject   error
}

func (s scheduledConsumerAuthority) ScheduleAdmission(ctx context.Context) (func(), error) {
	return s.schedule(ctx)
}

func (s scheduledConsumerAuthority) CheckPoolSpend(identity ledgerv4.SQLiteIdentity, facts protocolv4.PoolSpendFacts) error {
	if s.reject != nil {
		return s.reject
	}
	return s.poolSQLiteAuthority.CheckPoolSpend(identity, facts)
}

func TestConsumerPoolSchedulingKeepsOriginalBoundaryAndReleasesToken(t *testing.T) {
	for _, outcome := range []string{"commit", "zero-gate", "revoked", "authority-rejected", "schedule-failed", "missing-release"} {
		t.Run(outcome, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			a := f.reserve(t, context.Background())
			proof, err := f.trust.proof.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			calls, releases := 0, 0
			x, err := consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				if outcome == "zero-gate" {
					authority.admissionGate = nil
				}
				scheduled := scheduledConsumerAuthority{poolSQLiteAuthority: authority}
				if outcome == "authority-rejected" {
					scheduled.reject = ledgerv4.ErrConflict
				}
				scheduled.schedule = func(ctx context.Context) (func(), error) {
					calls++
					boundary, ok := ctx.(sqliteAdmissionScheduleContext)
					if !ok || boundary.Context != a.ctx || boundary.deadline != a.config.Initial.Deadline || boundary.wake != a.wake || boundary.guard == nil {
						t.Fatal("scheduler replaced the actual admission boundary")
					}
					if outcome == "schedule-failed" {
						return nil, context.Canceled
					}
					if outcome == "missing-release" {
						return nil, nil
					}
					release, err := authority.ScheduleAdmission(ctx)
					if err != nil {
						return nil, err
					}
					if outcome == "revoked" {
						f.trust.trust.rejected.Store(true)
					}
					return func() { releases++; release() }, nil
				}
				x, callErr := a.ConsumePoolSQLite(store, scheduled, f.trust.authority, proof, work)
				if len(authority.admissionGate) != 0 {
					t.Fatal("original consumer retained its shared store token after return")
				}
				return x, callErr
			})
			wantReleases := 1
			if outcome == "schedule-failed" || outcome == "missing-release" {
				wantReleases = 0
			}
			if calls != 1 || releases != wantReleases {
				t.Fatalf("original schedule/release calls = %d/%d", calls, releases)
			}
			if outcome == "commit" || outcome == "zero-gate" {
				if err != nil || x == nil || !a.committed || !a.activated {
					t.Fatal("scheduled original TxA-P failed", err)
				}
			} else if err == nil || x != nil || a.committed || a.activated || a.poolSpend != nil {
				t.Fatal("failed scheduling/guard/authority reached a durable consumer", err)
			}
		})
	}
}

func TestConsumerPoolBlockedSchedulerObservesCancellationExpiryAndClose(t *testing.T) {
	for _, outcome := range []string{"cancel", "expire", "close"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := admissionIntegration(t, ctx, "preauthorized_pool")
			a := f.reserve(t, ctx)
			proof, err := f.trust.proof.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			_, err = consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				authority.admissionGate <- struct{}{}
				defer func() { <-authority.admissionGate }()
				entered := make(chan struct{})
				scheduled := scheduledConsumerAuthority{poolSQLiteAuthority: authority, schedule: func(ctx context.Context) (func(), error) {
					close(entered)
					return authority.ScheduleAdmission(ctx)
				}}
				result := make(chan error, 1)
				go func() {
					x, err := a.ConsumePoolSQLite(store, scheduled, f.trust.authority, proof, work)
					if x != nil {
						err = errors.New("blocked consumer activated before store ownership")
					}
					result <- err
				}()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("original consumer did not enter its finite store scheduler")
				}
				var expected error
				switch outcome {
				case "cancel":
					cancel()
					expected = context.Canceled
				case "expire":
					f.trust.tick.Store(400)
					a.mu.Lock()
					a.signalLocked()
					a.mu.Unlock()
					expected = timev4.ErrExpired
				case "close":
					a.Close()
					expected = cryptov4.ErrClosed
				}
				select {
				case err := <-result:
					if !errors.Is(err, expected) {
						t.Fatalf("blocked original %s = %v", outcome, err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("blocked consumer ignored its original admission boundary")
				}
				if len(authority.admissionGate) != 1 || a.poolSpend != nil || a.committed || a.activated {
					t.Fatal("failed waiter released another owner's token or started a spend")
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func consumeSessionPool(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation, connect ...func(*ledgerv4.SQLiteStore, poolSQLiteAuthority, resourcev4.Reference) (*InitialExchange, error)) (*InitialExchange, error) {
	return authorityConsumePool(t, f.authorityFixture, a, connect...)
}
func withSessionSQLite(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, recordBytes uint32, run func(*ledgerv4.SQLiteStore, func(uint32, resourcev4.Vector) resourcev4.Reference) error) error {
	return authoritySessionSQLite(t, f.authorityFixture, a, identity, continuity, recordBytes, run)
}
