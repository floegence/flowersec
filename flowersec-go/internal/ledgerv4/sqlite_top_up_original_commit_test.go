package ledgerv4

import (
	"context"
	"errors"
	"testing"
)

func TestSQLiteTopUpOriginalCommitRequiresConfirmedAppend(t *testing.T) {
	for _, mode := range []string{"first_commit", "lost_confirmation", "expired_pending", "refused_guard"} {
		t.Run(mode, func(t *testing.T) {
			f := newTopUpServerFixture(t)
			request, wire := f.request(1, 1)
			if _, err := f.prepare(wire); err != nil {
				t.Fatal(err)
			}
			response, facts := serverTopUpResponse(t, request, 1, false, 0)
			originalExecer := f.server.store.execer
			guard := func() error { return nil }
			switch mode {
			case "lost_confirmation":
				fault := &sqliteExecFault{ExecerContext: originalExecer, afterCommit: func() error { return errors.New("lost confirmation") }}
				fault.commits.Store(1)
				f.server.store.execer = fault
			case "expired_pending":
				f.tick.Store(500)
			case "refused_guard":
				guard = func() error { return ErrOwner }
			}
			calls := 0
			original := func() {
				calls++
				state, err := f.server.readState()
				if err != nil || state.State != TopUpServerCommitted || state.Response != facts {
					t.Error("original right preceded durable response", state, err)
				}
			}
			state, err := f.server.commit(context.Background(), f.authority, wire, response, guard, original)
			f.server.store.execer = originalExecer
			switch mode {
			case "first_commit":
				if err != nil || calls != 1 || state.State != TopUpServerCommitted {
					t.Fatal(state, calls, err)
				}
			case "lost_confirmation":
				if !errors.Is(err, ErrUnknown) || calls != 0 {
					t.Fatal("uncertain commit recreated original right", calls, err)
				}
			case "expired_pending":
				if err != nil || calls != 0 || state.State != TopUpServerTerminal {
					t.Fatal(state, calls, err)
				}
			case "refused_guard":
				if !errors.Is(err, ErrOwner) || calls != 0 {
					t.Fatal(calls, err)
				}
				return
			}
			before := calls
			for range 2 {
				if _, err = f.server.commit(context.Background(), f.authority, wire, response, nil, original); err != nil {
					t.Fatal(err)
				}
				if calls != before {
					t.Fatal("historical row recreated original right", calls)
				}
			}
		})
	}
}
