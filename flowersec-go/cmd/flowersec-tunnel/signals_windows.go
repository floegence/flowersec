//go:build windows

package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

func notifySignals() []os.Signal {
	// Windows does not support Unix-style SIGHUP/SIGUSR* signals.
	return []os.Signal{os.Interrupt}
}

func printSignalHelp(w io.Writer) {
	fmt.Fprintln(w, "Signals:")
	fmt.Fprintln(w, "  CTRL+C: shutdown")
}

// handleSignal returns true if the signal was handled and the server should keep running.
//
// On Windows we don't support runtime toggles; any signal triggers shutdown.
func handleSignal(_ os.Signal, _ *log.Logger, _ func() error, _ *metricsController) bool {
	return false
}
