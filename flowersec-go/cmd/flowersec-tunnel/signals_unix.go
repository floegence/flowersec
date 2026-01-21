//go:build !windows

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
)

func notifySignals() []os.Signal {
	return []os.Signal{
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGHUP,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
	}
}

func printSignalHelp(w io.Writer) {
	fmt.Fprintln(w, "Signals:")
	fmt.Fprintln(w, "  SIGHUP: reload issuer keyset")
	fmt.Fprintln(w, "  SIGUSR1: enable metrics (requires --metrics-listen)")
	fmt.Fprintln(w, "  SIGUSR2: disable metrics")
}

// handleSignal returns true if the signal was handled and the server should keep running.
func handleSignal(sig os.Signal, logger *log.Logger, reloadKeys func() error, metrics *metricsController) bool {
	switch sig {
	case syscall.SIGHUP:
		if reloadKeys == nil {
			return true
		}
		if err := reloadKeys(); err != nil {
			logger.Printf("reload keys failed: %v", err)
		} else {
			logger.Printf("reloaded issuer keyset")
		}
		return true
	case syscall.SIGUSR1:
		if metrics == nil {
			logger.Printf("metrics server disabled (missing --metrics-listen)")
			return true
		}
		metrics.Enable()
		logger.Printf("metrics enabled")
		return true
	case syscall.SIGUSR2:
		if metrics != nil {
			metrics.Disable()
			logger.Printf("metrics disabled")
		}
		return true
	default:
		return false
	}
}
