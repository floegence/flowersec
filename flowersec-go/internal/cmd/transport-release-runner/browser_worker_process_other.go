//go:build !unix

package main

import "os/exec"

func configureBrowserWorkerCommand(_ *exec.Cmd) {}
