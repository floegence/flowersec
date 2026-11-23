//go:build unix

package weaknetsmoke

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestMain(testingMain *testing.M) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	weaknetSmokeContext = ctx
	code := testingMain.Run()
	stop()
	os.Exit(code)
}
