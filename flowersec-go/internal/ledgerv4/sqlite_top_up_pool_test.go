package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"os"
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

func TestSQLiteTopUpReopenAdmitsCompletePoolRecordsBeforeEpochWrite(t *testing.T) {
	for _, mutation := range []string{"record", "material_digest", "identity_digest", "sequence", "generation", "expiry", "pending_digest", "pending_identity"} {
		t.Run(mutation, func(t *testing.T) {
			server := newTopUpServerFixture(t)
			f, journal, config := newTerminalClient(t, server)
			ctx := context.Background()
			certificate := []byte{0xa0}
			request, _ := server.request(1, 1)
			request.Identity, _ = protocolv4.TopUpIdentityDigest(certificate)
			var err error
			request.Digest, err = protocolv4.ComputeTopUpRequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			if err = journal.Begin(ctx, request, certificate, []byte("original-key")); err != nil {
				t.Fatal(err)
			}
			batch, facts := topUpStoreBatch(t, request)
			if err = journal.Install(ctx, request, batch); err != nil {
				t.Fatal(err)
			}
			closeSQLite(t, journal.store)
			open := func() (*SQLiteTopUpJournal, error) {
				charge, e := SQLiteTopUpJournalCharge(f.backing.limits, config)
				if e != nil {
					t.Fatal(e)
				}
				value, e := OpenSQLiteTopUpJournal(ctx, f.backing, f.identity, f.continuity, config, f.reserve(charge, 1), f.environment)
				if value != nil {
					f.stores = append(f.stores, value.store)
				}
				return value, e
			}
			// Prove the current stored representation remains readable before
			// corrupting a single fact in an otherwise valid transaction group.
			journal, err = open()
			if err != nil {
				t.Fatal("valid reopen", err)
			}
			cert, key, material := make([]byte, config.IdentityBytes), make([]byte, config.KeyReferenceBytes), make([]byte, 65536)
			row, err := journal.ReadPoolNext(ctx, 0, cert, key, material)
			if err != nil || !row.Found || row.Entry != facts.Entries[0] || !bytes.Equal(cert[:row.CertificateBytes], certificate) || string(key[:row.KeyReferenceBytes]) != "original-key" {
				t.Fatal("valid original pool row", row, err)
			}
			s := journal.store
			switch mutation {
			case "record":
				err = s.exec("UPDATE pool SET record=x'01' WHERE sequence=?1", named(1, sqliteUint(1)))
				if err == nil {
					err = s.exec("UPDATE manifest SET pool_bytes=(SELECT sum(length(record)) FROM pool)")
				}
			case "material_digest", "identity_digest":
				err = s.exec("UPDATE pool SET "+mutation+"=zeroblob(32) WHERE sequence=?1", named(1, sqliteUint(1)))
			case "sequence":
				err = s.exec("UPDATE pool SET sequence=?1 WHERE sequence=?2", named(1, sqliteUint(3)), named(2, sqliteUint(1)))
			case "generation":
				err = s.exec("UPDATE pool SET generation=?1 WHERE sequence=?2", named(1, sqliteUint(2)), named(2, sqliteUint(1)))
			case "expiry":
				err = s.exec("UPDATE pool SET expiry=?1 WHERE sequence=?2", named(1, sqliteUint(1001)), named(2, sqliteUint(1)))
			case "pending_digest":
				request.Digest[0] ^= 1
				var encoded [1024]byte
				n, e := encodeTopUpRequest(encoded[:], request)
				if e != nil {
					t.Fatal(e)
				}
				err = s.exec("UPDATE manifest SET pending=?1", named(1, encoded[:n]))
			case "pending_identity":
				err = s.exec("UPDATE manifest SET identity=x'a1'")
			}
			if err != nil {
				t.Fatal(err)
			}
			closeSQLite(t, s)
			before, err := os.ReadFile(f.backing.path)
			if err != nil {
				t.Fatal(err)
			}
			refused, err := open()
			if refused != nil {
				t.Fatal("invalid storage returned a usable owner")
			}
			projection := storageFormatProjection(t, err)
			if projection.TransactionGroup != "flowersec-v4-topup-client" || projection.ObservedRevision != (StorageRevision{Known: true, Value: 3}) || projection.Reason != StorageFormatState {
				t.Fatal("bounded format refusal", projection)
			}
			after, err := os.ReadFile(f.backing.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal rewrote original history", err)
			}
		})
	}
}
