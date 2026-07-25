//go:build unix

package main

import (
	"os"
	"os/exec"
	"time"
)

func configureBrowserWorkerCommand(command *exec.Cmd) {
	if command == nil {
		return
	}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return command.Process.Signal(os.Interrupt)
	}
	command.WaitDelay = 35 * time.Second
}
