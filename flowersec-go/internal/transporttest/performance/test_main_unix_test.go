//go:build unix

package performance

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestMain(testingMain *testing.M) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	performanceTestContext = ctx
	code := testingMain.Run()
	stop()
	os.Exit(code)
}
