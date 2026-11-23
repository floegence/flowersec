package sqlite_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/adapters/sqlite/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

func TestPublishedCredentialSurvivesReopen(t *testing.T) {
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "ws", URL: "wss://edge.example/flowersec/v5/direct", TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{ChannelID: "sqlite-test"}, Endpoints: endpoints,
		RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "credentials.db")
	store, err := sqlite.Create(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	record := issued.AuthorizationRecord()
	if err := errors.Join(store.Publish(ctx, record), store.Close()); err != nil {
		t.Fatalf("publish and close: %v", err)
	}
	reopened, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := reopened.Revoke(ctx, issued.LookupKey()); err != nil {
		t.Fatalf("revoke persisted credential: %v", err)
	}
	if err := reopened.Publish(ctx, record); err == nil {
		t.Fatal("published a second record with the revoked credential's key")
	}
}
