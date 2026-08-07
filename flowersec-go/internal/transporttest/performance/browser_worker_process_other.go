//go:build !unix

package performance

import "os/exec"

func configureBrowserWorkerCommand(_ *exec.Cmd) {}
