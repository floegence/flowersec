package signalcleanup

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

var testContext = context.Background()

func TestMain(testingMain *testing.M) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	testContext = ctx
	code := testingMain.Run()
	stop()
	os.Exit(code)
}

func TestCleanupAfterSignal(t *testing.T) {
	ready := os.Getenv("FLOWERSEC_SIGNAL_READY")
	cleaned := os.Getenv("FLOWERSEC_SIGNAL_CLEANED")
	if ready == "" || cleaned == "" {
		t.Fatal("signal cleanup fixture requires marker paths")
	}
	t.Cleanup(func() {
		if err := os.WriteFile(cleaned, []byte("cleaned\n"), 0o600); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(ready, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	<-testContext.Done()
}
