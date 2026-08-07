//go:build linux

package linuxnetlab

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

var privilegedTestContext = context.Background()

func TestMain(testingMain *testing.M) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	privilegedTestContext = ctx
	code := testingMain.Run()
	stop()
	os.Exit(code)
}
