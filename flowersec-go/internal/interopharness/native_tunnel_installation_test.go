package interopharness

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTunnelInstallationFailureJoinsOriginalOwner(t *testing.T) {
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(cache, "flowersec-installation-failure-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	reports := filepath.Join(base, "reports")
	t.Setenv("FLOWERSEC_TEST_ARTIFACT_DIR", reports)
	for _, source := range []string{"pool", "live"} {
		t.Run(source, func(t *testing.T) {
			directory := filepath.Join(base, source)
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			// This HTTPS URL passes installation input screening but is not a
			// valid Origin in the signed route, so construction fails after the
			// original reporter and TLS resources have been allocated.
			ctx := context.Background()
			if source == "pool" {
				owner, err := PrepareNativeTunnelInstallation(ctx, directory, "https://parity.example/not-an-origin", NativeTunnelInstallationOptions{Carriers: [2]string{"websocket", "websocket"}, RegisteredServer: true})
				if owner != nil {
					defer owner.Close()
				}
				if err == nil || owner != nil {
					t.Fatal("invalid-route pool installation returned an owner or succeeded")
				}
			} else {
				owner, err := PrepareNativeLiveTunnelInstallation(ctx, directory, "https://parity.example/not-an-origin", NativeLiveTunnelInstallationOptions{Carriers: [2]string{"websocket", "websocket"}})
				if owner != nil {
					defer owner.Close()
				}
				if err == nil || owner != nil {
					t.Fatal("invalid-route live installation returned an owner or succeeded")
				}
			}
			for _, path := range []string{directory, reports} {
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 0 {
					t.Fatalf("failed construction retained its original owned resources at %s: entries=%d err=%v", path, len(entries), err)
				}
			}
		})
	}
}
