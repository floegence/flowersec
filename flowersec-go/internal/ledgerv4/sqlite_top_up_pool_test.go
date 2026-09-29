package ledgerv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestSQLiteTopUpPoolTakeAndExpiryPreserveAppliedHistory(t *testing.T) {
	for _, mode := range []string{"take", "unknown", "expire"} {
		t.Run(mode, func(t *testing.T) {
			server := newTopUpServerFixture(t)
			_, j, c := newTerminalClient(t, server)
			ctx := context.Background()
			certificate := []byte{0xa0}
			r, _ := server.request(1, 1)
			r.Identity, _ = protocolv4.TopUpIdentityDigest(certificate)
			var err error
			r.Digest, err = protocolv4.ComputeTopUpRequestDigest(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Begin(ctx, r, certificate, []byte("original-key")); err != nil {
				t.Fatal(err)
			}
			batch, facts := topUpStoreBatch(t, r)
			if err := j.Install(ctx, r, batch); err != nil {
				t.Fatal(err)
			}
			before, err := j.Recover(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cert, key, material := make([]byte, c.IdentityBytes), make([]byte, c.KeyReferenceBytes), make([]byte, 65536)
			row, err := j.ReadPoolNext(ctx, 0, cert, key, material)
			if err != nil || !row.Found || row.Entry != facts.Entries[0] || string(cert[:row.CertificateBytes]) != string(certificate) || string(key[:row.KeyReferenceBytes]) != "original-key" || string(material[:row.MaterialBytes]) != string([]byte{0xa1, 0, 1}) {
				t.Fatal("exact complete row", row, err)
			}
			wrong := row.Entry
			wrong.Identity[0] ^= 1
			if err = j.TakePool(ctx, wrong); !errors.Is(err, ErrConflict) {
				t.Fatal("substituted tuple removed", err)
			}
			original := j.store.execer
			if mode == "unknown" {
				fault := &sqliteExecFault{ExecerContext: original, afterCommit: func() error { return errors.New("lost take commit") }}
				fault.commits.Store(1)
				j.store.execer = fault
			}
			if mode == "expire" {
				if n, e := j.RemoveExpiredPool(ctx, 2); e != nil || n != 0 {
					t.Fatal("live row reclaimed", n, e)
				}
				server.tick.Store(1000)
				if err = j.TakePool(ctx, row.Entry); err == nil {
					t.Fatal("expired item authorized")
				}
				if n, e := j.RemoveExpiredPool(ctx, 1); e != nil || n != 1 {
					t.Fatal("bounded expiry", n, e)
				}
			} else {
				err = j.TakePool(ctx, row.Entry)
				if mode == "take" && err != nil || mode == "unknown" && !errors.Is(err, ErrUnknown) {
					t.Fatal("take result", err)
				}
			}
			j.store.execer = original
			if err = j.TakePool(ctx, row.Entry); err == nil {
				t.Fatal("duplicate take delivered")
			}
			next, err := j.ReadPoolNext(ctx, 0, cert, key, material)
			if err != nil || !next.Found || next.Entry != facts.Entries[1] {
				t.Fatal("take did not persist", next, err)
			}
			after, err := j.Recover(ctx)
			if err != nil || after != before {
				t.Fatal("local pool maintenance changed TopUp history", after, err)
			}
			if err = j.ConfirmAck(ctx, r, facts); err != nil {
				t.Fatal("pool use blocked history Ack", err)
			}
		})
	}
}
