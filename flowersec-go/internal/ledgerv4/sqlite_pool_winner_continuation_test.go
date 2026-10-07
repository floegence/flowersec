package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// These storage tests supply already verified facts, as sqlitePoolOriginal
// does. Registered tunnel parity exercises capture from the original outbox.
func poolWinnerContinuationFixture(t *testing.T) (*sqliteFixture, *SQLitePoolWinnerContinuation) {
	t.Helper()
	f := newSQLiteFixture(t, "")
	c := &SQLitePoolWinnerContinuation{store: f.create(), nonce: [32]byte{7}, reservation: f.reserve(SQLitePoolWinnerContinuationCharge(), 1)}
	t.Cleanup(c.Close)
	var err error
	c.shared, err = f.environment.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	c.storeRef, _, _, _, err = c.store.admissionReference(f.environment)
	if err != nil {
		t.Fatal(err)
	}
	fields := protocolv4.AdmissionFields{Source: "preauthorized_pool", Tenant: "tenant", WinnerAuthority: f.identity.Authority,
		Audience: "service", Issuer: [16]byte{1}, Lease: [16]byte{2}, CandidateSet: [32]byte{3}, Candidate: [16]byte{4},
		IssuedAt: 100, ActivationEnd: 500, SessionEnd: 1000}
	r := admissionRecord{fields: fields}
	c.leaseBytes, err = r.key(c.lease[:])
	if err != nil {
		t.Fatal(err)
	}
	c.projectionBytes, err = r.encodeParentWinner(c.projection[:])
	if err != nil {
		t.Fatal(err)
	}
	c.controlProjectionBytes, err = protocolv4.EncodePoolWinnerControlProjection(c.controlProjection[:], fields)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestPoolWinnerContinuationOnlyMatchesExistingSelection(t *testing.T) {
	for _, mode := range []string{"missing", "mismatch", "matching"} {
		t.Run(mode, func(t *testing.T) {
			_, c := poolWinnerContinuationFixture(t)
			store := c.store
			key := bytes.Clone(c.lease[:c.leaseBytes])
			projection := bytes.Clone(c.projection[:c.projectionBytes])
			if mode != "missing" {
				if mode == "mismatch" {
					projection[len(projection)-1] ^= 1
				}
				if err := store.matchParentWinner(context.Background(), key, projection, c.scratch[:], func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			nonce, _, control, err := c.Publication()
			if err != nil {
				t.Fatal(err)
			}
			nonce = bytes.Clone(nonce)
			if bytes.Equal(control, c.projection[:c.projectionBytes]) {
				t.Fatal("local storage encoding escaped onto control channel")
			}
			if _, _, _, err = c.Publication(); !errors.Is(err, ErrOwner) {
				t.Fatal("repeated publication", err)
			}
			if err = c.Continue(context.Background(), nonce, func() error { return nil }); !errors.Is(err, ErrOwner) {
				t.Fatal("continued before ACK", err)
			}
			if err = c.Acknowledge([]byte{7}); !errors.Is(err, ErrOwner) {
				t.Fatal("wrong ACK nonce", err)
			}
			if err = c.Acknowledge(nonce); err != nil {
				t.Fatal(err)
			}
			if err = c.Acknowledge(nonce); !errors.Is(err, ErrOwner) {
				t.Fatal("repeated ACK", err)
			}
			if err = c.Continue(context.Background(), []byte{7}, func() error { return nil }); !errors.Is(err, ErrOwner) {
				t.Fatal("wrong continuation nonce", err)
			}
			err = c.Continue(context.Background(), nonce, func() error { return nil })
			if mode == "matching" && err != nil || mode != "matching" && !errors.Is(err, ErrConflict) {
				t.Fatal("selection match", mode, err)
			}
			if err = c.Continue(context.Background(), nonce, func() error { return nil }); !errors.Is(err, ErrOwner) {
				t.Fatal("repeated continuation", err)
			}
			var scratch [8192]byte
			n, found, err := store.readParentWinner(key, scratch[:])
			if err != nil || found != (mode != "missing") || found && !bytes.Equal(scratch[:n], projection) {
				t.Fatal("continuation changed winner history", n, found, err)
			}
			count, err := store.scalar("SELECT winner_rows FROM manifest WHERE id=1")
			want := int64(1)
			if mode == "missing" {
				want = 0
			}
			if err != nil || count != want {
				t.Fatal("continuation changed winner count", count, err)
			}
		})
	}
}

func TestPoolWinnerContinuationCloseRetainsActiveBacking(t *testing.T) {
	f, c := poolWinnerContinuationFixture(t)
	nonce, _, projection, err := c.Publication()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Acknowledge(nonce); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer close(release)
	go func() {
		done <- c.Continue(context.Background(), nonce, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	before := f.root.Snapshot().Charged[resourcev4.SDKBytes]
	c.Close()
	if f.root.Snapshot().Charged[resourcev4.SDKBytes] != before || projection[0] == 0 || nonce[0] == 0 {
		t.Error("Close released active backing")
	}
	release <- struct{}{}
	if err = <-done; !errors.Is(err, ErrOwner) {
		t.Fatal("closed continuation survived guard", err)
	}
	if f.root.Snapshot().Charged[resourcev4.SDKBytes] >= before || !bytes.Equal(projection, make([]byte, len(projection))) || !bytes.Equal(nonce, make([]byte, len(nonce))) {
		t.Fatal("joined continuation retained backing")
	}
}

func TestOriginalRemoteWinnerCannotRetryOrCreateLocalWinner(t *testing.T) {
	for _, outcome := range []string{"matched", "unknown", "closed"} {
		t.Run(outcome, func(t *testing.T) {
			f, continuation := poolWinnerContinuationFixture(t)
			store := continuation.store
			nonce, lease, projection, err := continuation.Publication()
			if err != nil {
				t.Fatal(err)
			}
			nonce, lease, projection = bytes.Clone(nonce), bytes.Clone(lease), bytes.Clone(projection)
			if err = continuation.Acknowledge(nonce); err != nil {
				t.Fatal(err)
			}
			calls := 0
			unknown := errors.New("remote confirmation lost")
			continuation.originalRemoteMatcher = func(ctx context.Context, originalLease, originalProjection []byte, guard func() error) error {
				calls++
				if !bytes.Equal(originalLease, lease) || !bytes.Equal(originalProjection, projection) {
					t.Fatal("remote matcher did not receive the retained original selection")
				}
				if err := guard(); err != nil {
					return err
				}
				if outcome == "unknown" {
					return unknown
				}
				if outcome == "closed" {
					before := f.root.Snapshot().Charged[resourcev4.SDKBytes]
					continuation.Close()
					if f.root.Snapshot().Charged[resourcev4.SDKBytes] != before || !bytes.Equal(originalProjection, projection) {
						t.Fatal("Close released the active remote control custody")
					}
				}
				return ctx.Err()
			}
			err = continuation.Continue(context.Background(), nonce, func() error { return nil })
			if outcome == "matched" && err != nil || outcome == "unknown" && !errors.Is(err, unknown) || outcome == "closed" && !errors.Is(err, ErrOwner) {
				t.Fatal("incorrect original remote outcome", err)
			}
			if err = continuation.Continue(context.Background(), nonce, func() error { return nil }); !errors.Is(err, ErrOwner) || calls != 1 {
				t.Fatal("remote continuation was retried", calls, err)
			}
			count, err := store.scalar("SELECT winner_rows FROM manifest WHERE id=1")
			if err != nil || count != int64(0) {
				t.Fatal("remote confirmation created a local winner", count, err)
			}
		})
	}
}
