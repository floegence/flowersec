//go:build !unix

package browserworkload

import (
	"os/exec"
)

// Run rejects unsupported hosts before constructing any command or authority.
func configureRunnerCommand(command *exec.Cmd) {}
func terminateRunnerGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}
