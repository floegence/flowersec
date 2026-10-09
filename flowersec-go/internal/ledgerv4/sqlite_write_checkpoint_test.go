package ledgerv4

import (
	"context"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestSQLiteWriteCheckpointKeepsBoundedReusableDurableWAL(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	for lease := byte(1); lease <= 4; lease++ {
		a := sqliteOriginal(t, f, s, lease)
		if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := a.Cleanup(); err != nil {
			t.Fatal(err)
		}
		if err := s.checkpointForWrite(); err != nil {
			t.Fatal(err)
		}
		// Read the main file without WAL to prove the completed checkpoint,
		// then inspect actual allocation before the next transaction reuses it.
		if count := sqliteMainOnlyScalar(t, f.backing.path, "SELECT admission_rows FROM manifest WHERE id=1"); count != int64(lease) {
			t.Fatal("checkpoint left a committed fact only in WAL", count)
		}
		info, err := os.Stat(f.backing.path + "-wal")
		if err != nil || info.Size() <= 32 || info.Size() > int64(32+uint64(f.backing.limits.MaxPages)*(sqlitePageBytes+24)) {
			t.Fatal("reusable WAL escaped its original disk bound", info, err)
		}
	}
	closeSQLite(t, s)
	reopened, err := f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := reopened.scalar("SELECT admission_rows FROM manifest WHERE id=1"); err != nil || count != int64(4) {
		t.Fatal("restart lost durable admission history", count, err)
	}
}
