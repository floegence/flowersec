package protocolv4_test

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestSQLiteDirectIssuerMatureRetirementPreservesReplayHistory(t *testing.T) {
	f := newDirectSQLiteFixture(t)
	store := f.open(true)
	a := f.authority(store, f.config(2, 2))
	request := directSQLiteRequest(19)
	permit, err := a.BeginDirectIssue(context.Background(), request, f.h.Facts)
	if err != nil {
		t.Fatal(err)
	}
	permit.Close()
	if retired, err := a.RetireMature(context.Background(), request.RequestID); err != nil || retired {
		t.Fatal("retired without mature signed frontier", retired, err)
	}
	dst := make([]byte, 16384)
	publication, err := a.ReadNextObligation(context.Background(), [32]byte{}, dst)
	if err != nil || !publication.Found || publication.RequestID != request.RequestID || publication.LeaseID != f.h.Facts.LeaseID || publication.State != ledgerv4.DirectIssueReserved || publication.ArtifactDigest != ([32]byte{}) || publication.ConfigurationBytes == 0 || publication.ProjectionBytes == 0 || publication.RetirementBytes != 0 {
		t.Fatal("wrong original publisher observation", publication, err)
	}
	a.Close()
	protocolv4.InstallMatureDirectIssueNamespace(t, f.h, true)
	c := f.config(2, 2)
	a = f.authority(store, c)
	if retired, err := a.RetireMature(context.Background(), request.RequestID); err != nil || !retired {
		t.Fatal("actual full-State floor did not retire mature obligation", retired, err)
	}
	status, err := a.Status(context.Background())
	if err != nil || status.Outstanding != 0 || status.RetainedRequests != 1 {
		t.Fatal("retirement lost replay tombstone", status, err)
	}
	publication, err = a.ReadNextObligation(context.Background(), [32]byte{}, dst)
	if err != nil || !publication.Found || publication.State != ledgerv4.DirectIssueRetired || publication.RetirementBytes != 88 || publication.RequestID != request.RequestID {
		t.Fatal("retirement proof not retained", publication, err)
	}
	if next, err := a.ReadNextObligation(context.Background(), publication.RequestID, dst); err != nil || next.Found {
		t.Fatal("bounded cursor repeated original row", next, err)
	}
	if retired, err := a.RetireMature(context.Background(), request.RequestID); err != nil || !retired {
		t.Fatal("retirement was not idempotent", retired, err)
	}
	a.Close()
	previousEpoch := f.host.epoch
	closeDirectSQLite(t, store)
	a = f.authority(f.open(false), c)
	if f.host.epoch != previousEpoch+1 {
		t.Fatal("valid canonical retirement did not advance the reopened fence", previousEpoch, f.host.epoch)
	}
	status, err = a.Status(context.Background())
	if err != nil || status.Outstanding != 0 || status.RetainedRequests != 1 {
		t.Fatal("restart lost durable retirement/replay facts", status, err)
	}
	if p, err := a.BeginDirectIssue(context.Background(), request, f.h.Facts); err == nil || p != nil {
		t.Fatal("retired request recovered signing authority")
	}
}
