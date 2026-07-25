//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

const collectionCommandCleanupGrace = 35 * time.Second

func configureCollectionCommand(command *exec.Cmd) {
	if command == nil {
		return
	}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		if err := command.Process.Signal(os.Interrupt); err != nil {
			if errors.Is(err, os.ErrProcessDone) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	command.WaitDelay = collectionCommandCleanupGrace
}
