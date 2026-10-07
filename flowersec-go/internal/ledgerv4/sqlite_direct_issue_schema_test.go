package ledgerv4

import (
	"context"
	"testing"
)

func TestSQLiteIssuanceAggregateQuotaCoversOtherPurposeTables(t *testing.T) {
	f := newSQLiteFixtureWithLimits(t, "", SQLiteLimits{MaxPages: 64, MaxRecords: 1, MaxRecordBytes: 4096, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})
	s := f.create()
	if err := s.writeTransaction(context.Background(), func() error { return nil }, func() error {
		if err := s.exec("INSERT INTO direct_issue_config VALUES(1,x'01',1,1285,zeroblob(8),zeroblob(8))"); err != nil {
			return err
		}
		if err := s.exec("INSERT INTO issuance(lease,request,invocation,fence,state,version,artifact,projection) VALUES(zeroblob(34),zeroblob(32),zeroblob(16),?1,0,?1,zeroblob(32),x'01')", named(1, sqliteUint(1))); err != nil {
			return err
		}
		return s.exec("UPDATE manifest SET issuance_rows=1 WHERE id=1")
	}); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO admission VALUES(zeroblob(34),zeroblob(8),zeroblob(8),0,0,x'01')",
		"INSERT INTO spend VALUES(zeroblob(34),1,1,zeroblob(8),zeroblob(8),x'01')",
		"INSERT INTO parent_winner VALUES(zeroblob(34),x'01')",
	} {
		if err := s.exec(statement); err == nil {
			t.Fatal("another purpose exceeded the physical aggregate row cap")
		}
	}
	// A mature tombstone still consumes the same physical history slot.
	if err := s.exec("UPDATE issuance SET state=2,version=?1,retirement=zeroblob(88)", named(1, sqliteUint(2))); err != nil {
		t.Fatal(err)
	}
	if err := s.exec("UPDATE direct_issue_config SET rows=0,state_bytes=1152 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := s.exec("INSERT INTO parent_winner VALUES(zeroblob(34),x'01')"); err == nil {
		t.Fatal("retirement fabricated a free physical history slot")
	}
	closeSQLite(t, s)
	// Quota consistency alone cannot admit the intentionally opaque x'01'
	// configuration and obligation used by this physical-capacity fixture.
	opened, err := f.open(false)
	if opened != nil {
		t.Fatal("synthetic issuance bytes restored an authority")
	}
	storageFormatProjection(t, err)
}
